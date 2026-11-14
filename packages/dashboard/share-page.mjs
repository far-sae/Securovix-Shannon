// Read-only public pages for share links. Markdown is rendered with raw HTML escaped and only
// http(s)/mailto/relative links allowed, so a shared report cannot carry script into the viewer.
import { Marked } from 'marked';

const esc = (value) =>
  String(value ?? '').replace(
    /[&<>"']/g,
    (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch],
  );

const safeHref = (href) => {
  const value = String(href || '').trim();
  return /^(https?:|mailto:|\/(?!\/)|#)/i.test(value) ? value : null;
};

const markdown = new Marked({
  gfm: true,
  renderer: {
    html({ text }) {
      return esc(text);
    },
    link({ href, title, tokens }) {
      const inner = this.parser.parseInline(tokens);
      const url = safeHref(href);
      if (!url) return inner;
      return `<a href="${esc(url)}"${title ? ` title="${esc(title)}"` : ''} rel="noopener noreferrer nofollow">${inner}</a>`;
    },
    image({ text }) {
      return `<span class="img-alt">[image: ${esc(text)}]</span>`;
    },
  },
});

export function renderMarkdown(source) {
  return markdown.parse(String(source || ''));
}

const STYLE = `*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--t1);font-family:Inter,system-ui,sans-serif;line-height:1.7}
.wrap{max-width:860px;margin:0 auto;padding:36px 24px 80px}.top{display:flex;align-items:center;gap:10px;margin-bottom:28px;color:var(--t0);font-weight:700}
.top img{width:30px;height:30px;border-radius:8px}.meta{color:var(--t3);font-size:12.5px;margin:-8px 0 26px}h1,h2,h3{color:var(--t0);line-height:1.25}
h1{font-size:30px}h2{font-size:21px;margin-top:30px}a{color:var(--acc2)}code{background:var(--s2);padding:1px 5px;border-radius:5px}
pre{background:var(--s1);border:1px solid var(--brd);border-radius:10px;padding:14px;overflow:auto}pre code{background:none;padding:0}
table{border-collapse:collapse;width:100%;font-size:14px}th,td{border:1px solid var(--brd);padding:6px 10px;text-align:left}
.msg{border:1px solid var(--brd);background:var(--s1);border-radius:12px;padding:12px 16px;margin:12px 0}.msg.user{border-color:var(--brd2)}
.who{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--t3);font-weight:700}.img-alt{color:var(--t3)}
footer{border-top:1px solid var(--brd);margin-top:40px;padding-top:16px;font-size:12px;color:var(--t3)}`;

function shell(title, meta, body) {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>${esc(title)} · Securovix</title>
<link rel="icon" href="/favicon.png"><link rel="stylesheet" href="/tokens.css"><style>${STYLE}</style></head>
<body><main class="wrap"><div class="top"><img src="/favicon.png" alt="">Securovix · shared</div>
<h1>${esc(title)}</h1><div class="meta">${esc(meta)}</div>${body}
<footer>Shared read-only link. It expires automatically and can be revoked by the owner. <a href="/">Securovix</a></footer></main></body></html>`;
}

export function renderSharedResearch(report, link) {
  const meta = `Security assessment of ${report.domain} · generated ${new Date(report.createdAt).toUTCString()} · link expires ${new Date(link.expiresAt).toUTCString()}`;
  return shell(`Security assessment: ${report.domain}`, meta, renderMarkdown(report.markdown));
}

export function renderSharedConversation(conversation, link) {
  const meta = `Assistant conversation · link expires ${new Date(link.expiresAt).toUTCString()}`;
  const body = (conversation.messages || [])
    .filter((m) => m.role === 'user' || m.role === 'assistant')
    .map(
      (m) =>
        `<div class="msg ${m.role}"><div class="who">${m.role === 'user' ? 'Question' : 'Securovix assistant'}</div>${renderMarkdown(m.content)}</div>`,
    )
    .join('');
  return shell(conversation.title || 'Conversation', meta, body);
}

export function renderShareGone() {
  return shell(
    'Link unavailable',
    'This share link has expired, was revoked, or does not exist.',
    '<p>Ask the person who shared it for a new link.</p>',
  );
}
