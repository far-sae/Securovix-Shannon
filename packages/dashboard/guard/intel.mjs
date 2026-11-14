// Threat intelligence for Guard: known-bad IP addresses from free public feeds.
// Only the feed is downloaded; nothing about the organization is sent anywhere.
const FEEDS = [
  {
    source: 'abuse.ch Feodo Tracker',
    url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.json',
    parse: (json) =>
      (Array.isArray(json) ? json : []).map((row) => [
        row.ip_address,
        row.malware ? `${row.malware} botnet server` : 'botnet server',
      ]),
  },
];
const TTL = 6 * 60 * 60_000;
let cache = { at: 0, map: new Map(), errors: [] };

export function parseFeeds(results) {
  const map = new Map();
  for (const { feed, json } of results) {
    for (const [ip, label] of feed.parse(json)) {
      if (ip && /^[0-9a-f.:]+$/i.test(String(ip))) map.set(String(ip), { source: feed.source, label });
    }
  }
  return map;
}

export async function loadBadIps({ fetchImpl = fetch, now = Date.now(), force = false } = {}) {
  if (process.env.SHANNON_GUARD_INTEL === '0') return new Map();
  if (!force && cache.at && now - cache.at < TTL) return cache.map;
  const results = [];
  const errors = [];
  for (const feed of FEEDS) {
    try {
      const response = await fetchImpl(feed.url, {
        signal: AbortSignal.timeout(20_000),
        headers: { accept: 'application/json' },
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      results.push({ feed, json: await response.json() });
    } catch (error) {
      errors.push(`${feed.source}: ${error.message}`);
    }
  }
  // Keep the previous list if every feed failed, rather than forgetting every bad address.
  const map = results.length ? parseFeeds(results) : cache.map;
  cache = { at: now, map, errors };
  return map;
}

export function intelStatus() {
  return { loadedAt: cache.at || null, addresses: cache.map.size, errors: cache.errors };
}

export function setIntelForTests(map) {
  cache = { at: Date.now(), map, errors: [] };
}
