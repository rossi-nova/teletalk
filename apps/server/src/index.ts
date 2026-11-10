import 'dotenv/config';
import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadConfig, validateConfig } from './config.js';
import { createRoutes } from './gateway/routes.js';
import { SessionManager } from './gateway/session-manager.js';

const cfg = loadConfig();
const missing = validateConfig(cfg);

const app = new Hono();

// CORS（预览页可能从 file:// 或别的端口打开）
app.use("/*", async (c, next) => {
  c.header("Access-Control-Allow-Origin", "*");
  c.header("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  c.header("Access-Control-Allow-Headers", "Content-Type");
  if (c.req.method === "OPTIONS") return c.body(null, 204);
  await next();
});
const manager = new SessionManager(cfg.dingtalk);
app.route('/', createRoutes(manager));

app.get('/health', (c) => c.json({ ok: true, connected: manager.connected }));

// 预览页
const PREVIEW = join(dirname(fileURLToPath(import.meta.url)), '../../preview/index.html');
app.get('/', (c) => c.html(readFileSync(PREVIEW, 'utf8')));

serve({ fetch: app.fetch, port: cfg.port }, (info) => {
  console.log(`teletalk 网关: http://127.0.0.1:${info.port}`);
  if (missing.length) {
    console.warn('缺少配置，无法连接钉钉：');
    for (const m of missing) console.warn('  -', m);
  }
});

process.on('SIGINT', () => {
  manager.close();
  process.exit(0);
});
