# hthienproxyvip

Simple proxy app (Express + TypeScript) with an Admin UI to create/revoke API keys.

Features
- GET /proxy?url=<encoded_url> — proxies the target URL (requires API key)
- Admin UI at /admin (protected by HTTP Basic auth) to create/list/revoke keys
- Keys are hashed and stored in db/keys.json
- Dockerfile included
- Optional WHITELIST env var to restrict allowed proxy hosts

Environment
- PORT (default 3000)
- ADMIN_PASSWORD (required for /admin; username is 'admin')
- KEY_SALT (optional but recommended)
- WHITELIST (optional) — comma separated hostnames allowed

Run locally (dev)
1. cp .env.example .env and fill ADMIN_PASSWORD and KEY_SALT
2. npm install
3. npm run dev
4. Visit http://localhost:3000/admin (browser will prompt Basic auth: user=admin, pass=ADMIN_PASSWORD)

Build and run (production)
1. npm run build
2. npm start

Docker
- Build: docker build -t hthienproxyvip .
- Run: docker run -p 3000:3000 -e ADMIN_PASSWORD=yourpass -e KEY_SALT=salty hthienproxyvip

Quick usage
- Create API key at /admin → the created key is displayed once (store it).
- Use key in requests:
  - Header: x-api-key: YOUR_KEY
  - Or query: /proxy?url=...&api_key=YOUR_KEY

Security notes
- Do not commit .env with secrets.
- For production, use a proper DB or secret manager instead of db/keys.json.
- Use reverse proxy (Caddy/Nginx) for HTTPS (Caddy recommended for automatic TLS).
