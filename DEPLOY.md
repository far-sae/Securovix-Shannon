# How to put Securovix online — step by step

This guide gets your website live on the internet. You'll use 4 free services. Total time: about 30 minutes if you've never done this before.

## What does each service do?

| Service | What it does for us | Free? |
|---|---|---|
| **Supabase** | Stores user accounts and scores in a database | Yes |
| **Railway** | Runs the actual program (the brain) | $5 free credit |
| **Vercel** | Makes the website fast for users worldwide | Yes |
| **Google Console** | Lets people sign in with their Google account | Yes |

**The simple picture:**

```
   Visitor's browser
         ↓
       Vercel  ←  shows the website (fast, worldwide)
         ↓
       Railway ←  runs the code, talks to AI agents
         ↓
      Supabase ←  remembers users, saves scores
```

> **You can skip Vercel** if you want — Railway alone works too. Vercel just makes the site faster. Do Steps 1 and 3 (Supabase + Railway) at minimum.

---

## Step 1 · Set up Supabase (10 minutes) — REQUIRED

Supabase is your database. Without it, every time you update the site, all user accounts get wiped out.

### Make a Supabase account

1. Open <https://app.supabase.com> in your browser
2. Click **Sign in** (use your GitHub account — easiest)
3. Click the green **New project** button

### Fill in the project details

- **Name:** type `securovix`
- **Database Password:** click the **Generate a password** button. Copy the password somewhere safe — you probably won't need it but better safe than sorry.
- **Region:** pick the one closest to you. London or Frankfurt are good for Europe. New York for US East Coast.
- **Pricing Plan:** **Free** (default)

Click **Create new project**. Wait 2 minutes while Supabase builds your database.

### Create the tables (this stores users)

1. On the left sidebar, click **SQL Editor**
2. Click **New query** in the top-right
3. Open this file in your code editor: [`packages/dashboard/supabase/schema.sql`](packages/dashboard/supabase/schema.sql)
4. Select all the text in that file (Ctrl+A) and copy it (Ctrl+C)
5. Paste it into the Supabase SQL Editor box
6. Click the green **Run** button at the bottom right

You should see a success message. To confirm, click **Table Editor** on the left sidebar — you'll see two new tables: `shannon_users` and `shannon_leaderboard`. ✅

### Copy the secret keys (you'll need these in Step 3)

1. Left sidebar → click the gear icon (**Project Settings**)
2. Click **API** in the menu
3. You'll see two important things on this page. Open a notepad and copy them:

| What it's called on the page | Where you'll paste it later |
|---|---|
| **Project URL** | A box called `SUPABASE_URL` |
| **service_role** key (under "Project API keys" — click the **Reveal** button) | A box called `SUPABASE_SERVICE_ROLE_KEY` |

> ⚠ **Important:** Make sure you copy the **service_role** key, NOT the **anon** key. They look similar but the wrong one won't work. The `service_role` key is the longer one near the bottom.

> 🔒 **Never share the service_role key with anyone.** Don't put it in a screenshot, don't paste it in chat, don't commit it to GitHub. It's like the master key to your database.

---

## Step 2 · Set up Google Sign-In (5 minutes) — OPTIONAL

This lets people log in with their Google account instead of typing an email and password. Skip this whole step if you don't care — email/password works fine without it.

### Make a Google Cloud project

1. Open <https://console.cloud.google.com>
2. At the very top of the page, you'll see a project dropdown. Click it → **New Project**
3. Name it `securovix` and click **Create**

### Set up the consent screen (what people see when they click "Sign in with Google")

1. Left sidebar → **APIs & Services** → **OAuth consent screen**
2. Pick **External** → click **Create**
3. Fill in:
   - **App name:** `Securovix`
   - **User support email:** your email
   - **App logo:** upload [`packages/dashboard/public/favicon.png`](packages/dashboard/public/favicon.png) (optional, looks nice)
   - **Application home page:** leave blank for now (you'll add it after Step 3 or 4)
   - **Developer contact info:** your email
4. Click **Save and Continue**
5. On the **Scopes** page, just click **Save and Continue** again (default settings are fine)
6. On the **Test users** page, click **Add Users** → type your own Google email → click **Save and Continue**

### Create the actual sign-in button credentials

1. Left sidebar → **APIs & Services** → **Credentials**
2. Click **Create Credentials** → **OAuth client ID**
3. **Application type:** pick **Web application**
4. **Name:** `Securovix dashboard`
5. **Authorized JavaScript origins:** leave empty for now (you'll fill this in after Step 3)
6. **Authorized redirect URIs:** leave empty for now too
7. Click **Create**

A popup appears with your **Client ID** and **Client Secret**. Copy both into your notepad — you'll paste them into Railway in Step 3.

We'll come back here at the end of Step 3 to fill in the URLs.

---

## Step 3 · Set up Railway (10 minutes) — REQUIRED

Railway is where your actual code runs. This is what people's browsers talk to.

### Connect your GitHub repo

1. Open <https://railway.app>
2. Click **New Project** → **Deploy from GitHub repo**
3. Pick your Securovix repo from the list (you might need to click "Configure GitHub App" if it's the first time and grant Railway access)
4. Railway starts setting up. Click **Settings** (top right area).
5. Find **Root Directory** → type `shannon` → click somewhere to save (Railway saves automatically)

### Make a session secret (a random password the server uses)

Open a terminal on your computer and run:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

You'll see a long string of random letters and numbers. Copy it.

### Tell Railway about your secrets

1. In Railway, click the **Variables** tab (next to Settings)
2. Click **Raw Editor**
3. Paste this in (replace the `<...>` parts with your actual values):

```env
NODE_ENV=production
SHANNON_SESSION_SECRET=<paste the random string from above>

SUPABASE_URL=<paste the Project URL from Supabase Step 1>
SUPABASE_SERVICE_ROLE_KEY=<paste the service_role key from Supabase Step 1>

# Only if you did Step 2 — otherwise leave these out
GOOGLE_CLIENT_ID=<paste from Google Step 2>
GOOGLE_CLIENT_SECRET=<paste from Google Step 2>
```

4. Click **Update Variables**. Railway automatically rebuilds your site (takes 2-3 minutes).

### Get your public URL

1. Go back to **Settings** tab
2. Find **Networking** → **Public Networking** → click **Generate Domain**
3. Railway gives you a URL like `securovix-production-abc123.up.railway.app`
4. Copy this URL — this is your live site!

### Check that everything is working

Open this in your browser:

```
https://YOUR-RAILWAY-URL.up.railway.app/healthz
```

You should see:

```json
{"ok":true,"db":"supabase","uptime":12.3}
```

The important word is **`"db":"supabase"`** — that means Railway is talking to Supabase correctly.

❌ If you see `"db":"fs"` instead, something went wrong with the Supabase variables. Double-check Step 3 — make sure no extra spaces, and make sure you used the `service_role` key not `anon`.

### Now go back and finish Google Sign-In (if you set it up)

If you did Step 2, go back to <https://console.cloud.google.com> → **Credentials** → click your OAuth client → and now fill in the URLs:

- **Authorized JavaScript origins:** `https://YOUR-RAILWAY-URL.up.railway.app`
- **Authorized redirect URIs:** `https://YOUR-RAILWAY-URL.up.railway.app/auth/google/callback`

Click **Save**.

🎉 At this point your site is LIVE. People can visit your Railway URL, sign up, sign in, and use everything. If you don't care about Vercel, you're done.

---

## Step 4 · Set up Vercel (5 minutes) — OPTIONAL

Vercel makes your website faster for visitors all over the world. Skip this if you only have users near your Railway region — Railway alone is fine.

### Update vercel.json with your Railway URL

1. Open [`vercel.json`](vercel.json) in your code editor
2. Find these 3 lines that say `REPLACE-WITH-RAILWAY-URL.up.railway.app`
3. Replace all 3 with your actual Railway URL from Step 3
4. Save the file
5. Push to GitHub (`git add vercel.json && git commit -m "wire vercel to railway" && git push`)

### Deploy on Vercel

1. Open <https://vercel.com>
2. Click **Add New** → **Project**
3. Pick your Securovix repo
4. **Configure Project:**
   - **Root Directory:** click **Edit**, type `shannon`, click **Continue**
   - **Framework Preset:** pick **Other**
   - Leave everything else as default — Vercel reads it from `vercel.json`
5. **Environment Variables:** leave empty (Vercel doesn't need any — all secrets stay on Railway)
6. Click **Deploy**. Takes about 30 seconds.

### Get your Vercel URL

After deployment, Vercel shows you a URL like `securovix-abc123.vercel.app`. This is your fast public site!

### Use a custom domain (optional, looks more professional)

If you own a domain like `securovix.com`:

1. Vercel project → **Settings** → **Domains**
2. Click **Add** → type `securovix.com` → **Add**
3. Vercel shows you DNS records to add at your domain registrar (GoDaddy, Namecheap, Cloudflare, etc.)
4. Add those DNS records on your registrar's website
5. Wait 1-5 minutes — Vercel will issue an SSL certificate automatically

### Update Google Sign-In (if you set it up)

Go back to Google Console → **Credentials** → your OAuth client and ADD your Vercel URL to the JavaScript origins:

- **Authorized JavaScript origins:** ADD `https://your-vercel-domain.vercel.app` (keep the Railway one too)

Don't change the **redirect URI** — leave it pointing at Railway.

---

## How to test that everything works

Open your live site (Vercel URL if you did Step 4, otherwise Railway URL) in a browser:

1. Click **Create account**
2. Tick the **Terms and Privacy** checkbox
3. Sign up with a test email
4. You should land on the dashboard

Now go to Supabase → **Table Editor** → **shannon_users** — you should see your account row with the consent details filled in. ✅

---

## Common problems and fixes

| What you see | Why it's happening | How to fix |
|---|---|---|
| `/healthz` shows `"db":"fs"` not `"db":"supabase"` | The Supabase variables didn't take effect | Recheck Railway → Variables. Look for stray spaces. Click "Update Variables" again to force a redeploy. |
| Google Sign-In shows `redirect_uri_mismatch` | Google Console doesn't know about your URL yet | Add `https://YOUR-RAILWAY-URL/auth/google/callback` to **Authorized redirect URIs** in Google Console |
| Vercel pages load but `/api/...` returns errors | Wrong Railway URL in `vercel.json` | Edit `vercel.json`, fix the URL in all 3 places, push to GitHub |
| Sign-up fails with "Bad request" | Missing the Terms/Privacy checkbox | Tick the checkbox before clicking Create Account |
| `Supabase POST /shannon_users → 401` in Railway logs | You used the wrong Supabase key | Replace `SUPABASE_SERVICE_ROLE_KEY` with the **service_role** key (not `anon`) |

---

## Things to know after launch

- **One Railway server is enough for now.** If you ever get a lot of users at the same time, you'll need to upgrade the database setup. Don't worry about this until you have hundreds of users daily.

- **Long scans work fine.** Railway lets your code run for as long as it needs (unlike Vercel's serverless functions which timeout after a few minutes).

- **Scan files get wiped when you redeploy.** Each scan saves files to a folder on Railway, but those disappear when you push a new version. The scan results show up live in the dashboard while running, so this isn't a big problem yet — but if you want to keep old scan files long-term, you'll need to add Supabase Storage (a future improvement).

- **Code Scan works fully on Railway right now.** New Scan (web pentest) needs some extra security tools (`nmap`, `chromium`, etc.) installed in the container. The current Dockerfile only has Node.js. So Code Scan = full feature, New Scan = needs extra setup later.

- **Working on your laptop still works.** When you run `node packages/dashboard/server.mjs` locally without setting Supabase variables, the code automatically falls back to saving everything in `~/.shannon/users.json` like before. You don't need to change anything for local development.

---

## All the files used for deployment

```
shannon/
  Dockerfile.dashboard     ← How Railway builds your site
  railway.json             ← Tells Railway where to find Dockerfile.dashboard
  vercel.json              ← Tells Vercel to forward /api requests to Railway
  .env.example             ← Template showing all the secrets you need
  DEPLOY.md                ← This guide
  packages/dashboard/
    db.mjs                 ← The new database code (Supabase or local files)
    server.mjs             ← Updated to use the new database code
    supabase/
      schema.sql           ← The database tables (paste into Supabase SQL Editor)
    public/
      terms.html           ← Terms of Service page
      privacy.html         ← Privacy Policy page
```

---

## Stuck?

If something isn't working, copy the error message and tell me what step you're on. The most common issues are in the table above — start there.
