// Securovix Defender on Vercel — works with any framework (Vite, Astro, static sites).
//
// 1. Save this file as `middleware.js` in the root of the project you deploy to Vercel.
// 2. Add @securovix/defender to that project (or copy `web.mjs` and `signatures.mjs` from the
//    package into it and change the import path below — the two files have no other dependencies).
// 3. Optional: set SECUROVIX_DEFENDER_KEY in Vercel → Settings → Environment Variables to see
//    detections in your Securovix dashboard. Without it the defender still runs, locally.
// 4. Deploy in 'monitor' mode first. When the dashboard shows only real attacks, change to 'enforce'.
import { createWebDefender, vercelNext } from '@securovix/defender/web';

const defend = createWebDefender({
  apiKey: process.env.SECUROVIX_DEFENDER_KEY,
  mode: process.env.SECUROVIX_DEFENDER_MODE === 'enforce' ? 'enforce' : 'monitor',
  honeypot: true, // /.env, /.git/config, /wp-login.php … → 404 and an instant ban
  scanners: true, // sqlmap, nikto, nuclei … → 403 and an instant ban
  ban: { threshold: 5, windowMs: 60_000, ttlMs: 15 * 60_000 },
});

export default async function middleware(request, context) {
  // A Response means "stop here"; null means the request is fine and Vercel should carry on.
  return (await defend(request, context)) ?? vercelNext();
}

// Static assets carry no input. Skipping them keeps them on the CDN fast path.
export const config = {
  matcher: ['/((?!assets/|.*\\.(?:js|css|png|jpg|jpeg|gif|svg|webp|avif|ico|woff2?|map)$).*)'],
};
