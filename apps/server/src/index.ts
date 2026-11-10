import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { loadConfig, validateConfig } from './config.js';
import { createRoutes } from './gateway/routes.js';
import { SessionManager } from './gateway/session-manager.js';

const cfg = loadConfig();
const missing = validateConfig(cfg);

const app = new Hono();
const manager = new SessionManager(cfg.dingtalk);
app.route('/', createRoutes(manager));

app.get('/health', (c) => c.json({ ok: true, connected: manager.connected }));

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
