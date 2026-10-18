import fs from 'fs/promises';
import path from 'path';
import crypto from 'crypto';

const DB_DIR = path.join(__dirname, '..', 'db');
const DB_FILE = path.join(DB_DIR, 'keys.json');
const SALT = process.env.KEY_SALT || '';

type StoredKey = {
  id: string;
  hash: string;
  name?: string;
  created_at: string;
  revoked: boolean;
};

async function ensureDb() {
  try {
    await fs.mkdir(DB_DIR, { recursive: true });
    try {
      await fs.access(DB_FILE);
    } catch {
      await fs.writeFile(DB_FILE, JSON.stringify([]), 'utf8');
    }
  } catch (err) {
    console.error('Failed to ensure DB file', err);
    throw err;
  }
}

async function loadAll(): Promise<StoredKey[]> {
  await ensureDb();
  const raw = await fs.readFile(DB_FILE, 'utf8');
  try {
    return JSON.parse(raw) as StoredKey[];
  } catch {
    return [];
  }
}

async function saveAll(keys: StoredKey[]) {
  await ensureDb();
  await fs.writeFile(DB_FILE, JSON.stringify(keys, null, 2), 'utf8');
}

function hashKey(key: string): string {
  if (SALT) {
    return crypto.createHmac('sha256', SALT).update(key).digest('hex');
  }
  return crypto.createHash('sha256').update(key).digest('hex');
}

export async function createKey(name?: string) {
  const plain = crypto.randomBytes(24).toString('hex'); // 48 hex chars
  const id = crypto.randomUUID();
  const hash = hashKey(plain);
  const now = new Date().toISOString();
  const keys = await loadAll();
  keys.push({ id, hash, name, created_at: now, revoked: false });
  await saveAll(keys);
  return { id, key: plain, name, created_at: now };
}

export async function listKeys() {
  const keys = await loadAll();
  return keys.map(k => ({
    id: k.id,
    name: k.name,
    created_at: k.created_at,
    revoked: k.revoked,
  }));
}

export async function revokeKey(id: string) {
  const keys = await loadAll();
  const idx = keys.findIndex(k => k.id === id);
  if (idx === -1) return false;
  keys[idx].revoked = true;
  await saveAll(keys);
  return true;
}

export async function validateKey(provided: string) {
  const keys = await loadAll();
  const providedHash = hashKey(provided);

  for (const k of keys) {
    const a = Buffer.from(k.hash);
    const b = Buffer.from(providedHash);
    if (a.length === b.length && crypto.timingSafeEqual(a, b) && !k.revoked) {
      return { valid: true, id: k.id, name: k.name };
    }
  }
  return { valid: false };
}
