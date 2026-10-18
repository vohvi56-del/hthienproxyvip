import express from 'express';
import httpProxy from 'http-proxy';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import morgan from 'morgan';
import dotenv from 'dotenv';
import { URL } from 'url';
import path from 'path';
import { createKey, listKeys, revokeKey, validateKey } from './keystore';

dotenv.config();

const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
const WHITELIST = process.env.WHITELIST || ''; // comma-separated hosts (optional)
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || ''; // required to access /admin
if (!ADMIN_PASSWORD) {
  console.warn('Warning: ADMIN_PASSWORD is not set. Admin UI will be inaccessible.');
}

const app = express();

// Middleware
app.use(helmet());
app.use(morgan('combined'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// Serve static landing and admin UI
app.use(express.static(path.join(__dirname, '..', 'public')));

// Helper: check whitelist if configured
function isAllowedHost(hostname: string): boolean {
  if (!WHITELIST) return true;
  const list = WHITELIST.split(',').map(h => h.trim().toLowerCase()).filter(Boolean);
  return list.includes(hostname.toLowerCase());
}

const proxy = httpProxy.createProxyServer({
  changeOrigin: true,
  secure: false,
  xfwd: true,
});

proxy.on('error', (err, req, res) => {
  console.error('Proxy error:', err);
  if (!res.headersSent) {
    res.writeHead(502, { 'Content-Type': 'text/plain' });
  }
  try { res.end('Bad gateway. Proxy error.'); } catch (e) {}
});

// Admin basic auth middleware
function requireAdmin(req: express.Request, res: express.Response, next: express.NextFunction) {
  if (!ADMIN_PASSWORD) return res.status(503).send('Admin not configured.');
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Basic ')) {
    res.setHeader('WWW-Authenticate', 'Basic realm="admin"');
    return res.status(401).send('Authentication required.');
  }
  const payload = Buffer.from(auth.replace('Basic ', ''), 'base64').toString('utf8');
  const [user, pass] = payload.split(':');
  if (user !== 'admin' || pass !== ADMIN_PASSWORD) {
    res.setHeader('WWW-Authenticate', 'Basic realm="admin"');
    return res.status(401).send('Invalid credentials.');
  }
  next();
}

// Admin endpoints
app.post('/admin/api-keys', requireAdmin, async (req, res) => {
  const name = typeof req.body.name === 'string' ? req.body.name : undefined;
  try {
    const created = await createKey(name);
    return res.json({ id: created.id, key: created.key, name: created.name, created_at: created.created_at });
  } catch (err) {
    console.error('Failed create key', err);
    return res.status(500).send('Failed to create key');
  }
});

app.get('/admin/api-keys', requireAdmin, async (_, res) => {
  try {
    const keys = await listKeys();
    return res.json(keys);
  } catch (err) {
    console.error('Failed list keys', err);
    return res.status(500).send('Failed to list keys');
  }
});

app.post('/admin/api-keys/:id/revoke', requireAdmin, async (req, res) => {
  const id = req.params.id;
  try {
    const ok = await revokeKey(id);
    if (!ok) return res.status(404).send('Key not found');
    return res.json({ revoked: true });
  } catch (err) {
    console.error('Failed revoke', err);
    return res.status(500).send('Failed to revoke key');
  }
});

// Helper to extract API key from header or query
function extractApiKey(req: express.Request): string | null {
  const h = req.header('x-api-key');
  if (h) return h;
  if (req.query.api_key && typeof req.query.api_key === 'string') return req.query.api_key;
  return null;
}

// Main proxy endpoint: requires API key
app.get('/proxy', async (req, res) => {
  const rawUrl = req.query.url as string | undefined;
  if (!rawUrl) {
    return res.status(400).send('Missing url parameter.');
  }

  let target: URL;
  try {
    target = new URL(rawUrl);
  } catch (err) {
    return res.status(400).send('Invalid URL.');
  }

  if (target.protocol !== 'http:' && target.protocol !== 'https:') {
    return res.status(400).send('Protocol not supported.');
  }

  if (!isAllowedHost(target.hostname)) {
    return res.status(403).send('Host not allowed by whitelist.');
  }

  const apiKey = extractApiKey(req);
  if (!apiKey) return res.status(401).send('Missing API key (x-api-key header or api_key query).');

  const v = await validateKey(apiKey);
  if (!v.valid) return res.status(403).send('Invalid or revoked API key.');

  (req as any).url = target.pathname + target.search;
  const targetOrigin = target.origin;
  proxy.web(req, res, { target: targetOrigin });
});

// health
app.get('/health', (_, res) => res.json({ status: 'ok' }));

// Fallback: send index.html for other routes (SPA support)
app.get('*', (_, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`hthienproxyvip proxy running on port ${PORT}`);
  if (ADMIN_PASSWORD) console.log('Admin UI protected by HTTP Basic auth (user: admin)');
});
