#!/usr/bin/env node
/**
 * TLS / SSL configuration testing — the first non-web (transport-layer) proof module. Everything
 * here is an OBSERVED FACT from a real handshake (a protocol negotiated, a certificate presented,
 * an OpenSSL verification error), so it is zero-false-positive by nature. Connecting to host:443 is
 * safe and needs no new authorization beyond the domain the client already verified.
 *
 * Checks: deprecated protocols (TLS 1.0 / 1.1), expired / self-signed / hostname-mismatch / weak-key
 * certificates, near-expiry certs, and best-effort weak-cipher support (limited to ciphers the local
 * OpenSSL will still offer — modern builds disable RC4/EXPORT, so 3DES is the usual catch).
 */

import tls from 'node:tls';

function tlsConnect(host, port, opts = {}, timeoutMs = 8000) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => {
      if (done) return;
      done = true;
      resolve(v);
    };
    let socket;
    const isIp = /^\d{1,3}(\.\d{1,3}){3}$|:/.test(host); // SNI must not be an IP (RFC 6066)
    try {
      socket = tls.connect(
        { host, port, rejectUnauthorized: false, ...(isIp ? {} : { servername: host }), ...opts },
        () => {
          finish({
            ok: true,
            authError: socket.authorizationError || null,
            protocol: socket.getProtocol ? socket.getProtocol() : null,
            cert: socket.getPeerCertificate ? socket.getPeerCertificate() : {},
            cipher: socket.getCipher ? socket.getCipher() : null,
          });
          try {
            socket.end();
          } catch {}
        },
      );
    } catch (e) {
      return finish({ ok: false, error: e.code || e.message });
    }
    socket.setTimeout(timeoutMs, () => {
      try {
        socket.destroy();
      } catch {}
      finish({ ok: false, error: 'timeout' });
    });
    socket.on('error', (e) => finish({ ok: false, error: e.code || e.message }));
  });
}

// Returns [{tool, severity, target, detail, raw}] — the same finding shape the engine records.
export async function runTlsScan(host, port = 443) {
  const findings = [];
  const F = (severity, detail) => ({
    tool: 'tls-config',
    severity,
    target: `${host}:${port}`,
    detail,
    raw: JSON.stringify({ tool: 'tls-config', detail }),
  });

  const base = await tlsConnect(host, port);
  if (!base.ok) return findings; // not TLS / unreachable → nothing to assert

  // ── Certificate verification errors (OpenSSL's own verdict) ──
  const ae = base.authError;
  if (ae === 'CERT_HAS_EXPIRED') findings.push(F('high', 'TLS certificate has EXPIRED'));
  else if (ae === 'DEPTH_ZERO_SELF_SIGNED_CERT' || ae === 'SELF_SIGNED_CERT_IN_CHAIN')
    findings.push(F('medium', 'TLS certificate is self-signed (not issued by a trusted CA)'));
  else if (ae === 'ERR_TLS_CERT_ALTNAME_INVALID')
    findings.push(F('medium', `TLS certificate does not cover the hostname (${host})`));
  else if (ae === 'CERT_NOT_YET_VALID') findings.push(F('medium', 'TLS certificate is not yet valid'));

  // ── Certificate facts (expiry window, weak key) ──
  const cert = base.cert || {};
  if (cert.valid_to) {
    const daysLeft = (new Date(cert.valid_to).getTime() - Date.now()) / 86_400_000;
    if (daysLeft < 0 && ae !== 'CERT_HAS_EXPIRED') findings.push(F('high', 'TLS certificate has EXPIRED'));
    else if (daysLeft >= 0 && daysLeft < 14)
      findings.push(F('low', `TLS certificate expires in ${Math.floor(daysLeft)} day(s)`));
  }
  // Weak key: RSA < 2048 bits (EC keys report smaller bit counts but are strong → skip when a curve is present).
  if (cert.bits && cert.bits < 2048 && !cert.nistCurve && !cert.asn1Curve)
    findings.push(F('medium', `TLS certificate uses a weak ${cert.bits}-bit key (RSA < 2048)`));

  // ── Deprecated protocol versions ──
  for (const [ver, label] of [
    ['TLSv1', 'TLS 1.0'],
    ['TLSv1.1', 'TLS 1.1'],
  ]) {
    // @SECLEVEL=0 lets our client offer legacy ciphers, so the handshake actually completes when a
    // real server still supports the old protocol (otherwise the check would false-negative).
    const r = await tlsConnect(host, port, { minVersion: ver, maxVersion: ver, ciphers: 'DEFAULT@SECLEVEL=0' });
    if (r.ok && r.protocol === ver)
      findings.push(F('medium', `Deprecated ${label} protocol is supported (disable it — TLS 1.2+ only)`));
  }

  // ── Weak cipher (best-effort; limited to ciphers the local OpenSSL will offer) ──
  try {
    const wc = await tlsConnect(host, port, {
      ciphers: 'DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:RC4-SHA:RC4-MD5:NULL-SHA:@SECLEVEL=0',
      minVersion: 'TLSv1',
      maxVersion: 'TLSv1.2',
    });
    if (wc.ok && wc.cipher?.name && /rc4|3des|des-cbc3|null|export|md5/i.test(wc.cipher.name))
      findings.push(F('medium', `Weak TLS cipher accepted: ${wc.cipher.name}`));
  } catch {}

  return findings;
}
