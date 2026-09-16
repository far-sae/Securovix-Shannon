import { randomUUID } from 'node:crypto';
import { lookup } from 'node:dns/promises';
import { isPrivateAddress } from '../defender-edge/server.mjs';
import { appendDelivery, enqueueJob, getIntegration, listIntegrations } from './enterprise-db.mjs';
import { decryptSecret } from './enterprise-security.mjs';

async function publicUrl(raw) {
  const url = new URL(raw);
  if (url.protocol !== 'https:' && !(process.env.NODE_ENV !== 'production' && url.protocol === 'http:')) {
    throw new Error('integration URL must use HTTPS');
  }
  const addresses = await lookup(url.hostname, { all: true, verbatim: true });
  if (!addresses.length || addresses.some((item) => isPrivateAddress(item.address))) {
    throw new Error('integration URL must resolve only to public addresses');
  }
  return url;
}

async function request(url, options) {
  const target = await publicUrl(url);
  const response = await fetch(target, { signal: AbortSignal.timeout(15_000), redirect: 'error', ...options });
  const text = await response.text().catch(() => '');
  if (!response.ok) throw new Error(`integration returned ${response.status}: ${text.slice(0, 300)}`);
  return { status: response.status, body: text.slice(0, 2000) };
}

function eventText(event) {
  const data = event.data || {};
  const severity = data.severity ? `[${String(data.severity).toUpperCase()}] ` : '';
  return `${severity}${data.title || event.type}${data.status ? ` (${data.status})` : ''}`;
}

export async function sendEmail({ to, subject, text, html }) {
  if (process.env.RESEND_API_KEY) {
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { authorization: `Bearer ${process.env.RESEND_API_KEY}`, 'content-type': 'application/json' },
      body: JSON.stringify({
        from: process.env.SHANNON_EMAIL_FROM || 'Securovix Shannon <noreply@securovix.com>',
        to: [to],
        subject,
        text,
        html: html || undefined,
      }),
      signal: AbortSignal.timeout(15_000),
    });
    if (!response.ok)
      throw new Error(`email provider returned ${response.status}: ${(await response.text()).slice(0, 240)}`);
    return { provider: 'resend', accepted: true };
  }
  if (process.env.SHANNON_EMAIL_WEBHOOK_URL) {
    const headers = { 'content-type': 'application/json' };
    if (process.env.SHANNON_EMAIL_WEBHOOK_TOKEN)
      headers.authorization = `Bearer ${process.env.SHANNON_EMAIL_WEBHOOK_TOKEN}`;
    await request(process.env.SHANNON_EMAIL_WEBHOOK_URL, {
      method: 'POST',
      headers,
      body: JSON.stringify({ to, subject, text, html: html || null }),
    });
    return { provider: 'webhook', accepted: true };
  }
  if (process.env.NODE_ENV === 'production') throw new Error('email delivery is not configured');
  console.log(`[email:development] to=${to} subject=${subject}\n${text}`);
  return { provider: 'console', accepted: true };
}

export async function queueIntegrationEvent(orgId, event, userId = null, onlyIntegrationId = null) {
  const integrations = (await listIntegrations(orgId, { includeSecrets: true })).filter((item) => item.enabled);
  const jobs = [];
  for (const integration of integrations) {
    if (onlyIntegrationId && integration.id !== onlyIntegrationId) continue;
    jobs.push(
      await enqueueJob({
        orgId,
        userId,
        type: 'integration-delivery',
        payload: { integrationId: integration.id, event },
        maxAttempts: 5,
        idempotencyKey: event.id ? `${integration.id}:${event.id}` : null,
      }),
    );
  }
  return jobs;
}

export async function deliverIntegrationJob(job) {
  const integrationId = job.payload?.integrationId;
  const event = job.payload?.event;
  const integration = integrationId && (await getIntegration(job.orgId, integrationId));
  if (!integration || !integration.enabled) throw new Error('integration is missing or disabled');
  const secret = decryptSecret(integration.secretEnc) || {};
  const config = integration.config || {};
  const delivery = {
    id: randomUUID(),
    orgId: job.orgId,
    integrationId,
    eventType: event?.type || 'unknown',
    status: 'failed',
    attempt: job.attempts,
    createdAt: Date.now(),
  };
  try {
    let result;
    if (integration.type === 'webhook' || integration.type === 'siem-http') {
      const headers = { 'content-type': 'application/json', ...(secret.headers || {}) };
      if (secret.token) headers.authorization = `Bearer ${secret.token}`;
      result = await request(config.url, { method: 'POST', headers, body: JSON.stringify(event) });
    } else if (integration.type === 'slack') {
      result = await request(secret.webhookUrl || config.url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ text: `Securovix Shannon: ${eventText(event)}` }),
      });
    } else if (integration.type === 'teams') {
      result = await request(secret.webhookUrl || config.url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          type: 'message',
          attachments: [
            {
              contentType: 'application/vnd.microsoft.card.adaptive',
              content: {
                type: 'AdaptiveCard',
                version: '1.4',
                body: [{ type: 'TextBlock', text: eventText(event), wrap: true }],
              },
            },
          ],
        }),
      });
    } else if (integration.type === 'jira') {
      const base = String(config.baseUrl || '').replace(/\/$/, '');
      result = await request(`${base}/rest/api/3/issue`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: `Basic ${Buffer.from(`${secret.email}:${secret.apiToken}`).toString('base64')}`,
        },
        body: JSON.stringify({
          fields: {
            project: { key: config.projectKey },
            issuetype: { name: config.issueType || 'Task' },
            summary: eventText(event).slice(0, 240),
            description: {
              type: 'doc',
              version: 1,
              content: [{ type: 'paragraph', content: [{ type: 'text', text: JSON.stringify(event.data || {}) }] }],
            },
          },
        }),
      });
    } else if (integration.type === 'linear') {
      result = await request('https://api.linear.app/graphql', {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: secret.apiKey },
        body: JSON.stringify({
          query: 'mutation($input: IssueCreateInput!) { issueCreate(input: $input) { success issue { id url } } }',
          variables: {
            input: {
              teamId: config.teamId,
              title: eventText(event).slice(0, 240),
              description: JSON.stringify(event.data || {}, null, 2),
            },
          },
        }),
      });
    } else {
      throw new Error(`unsupported integration type: ${integration.type}`);
    }
    delivery.status = 'succeeded';
    delivery.responseStatus = result.status;
    delivery.completedAt = Date.now();
    await appendDelivery(delivery);
    return result;
  } catch (error) {
    delivery.error = String(error?.message || error).slice(0, 1000);
    delivery.completedAt = Date.now();
    await appendDelivery(delivery);
    throw error;
  }
}
