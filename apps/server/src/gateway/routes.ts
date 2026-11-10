/**
 * 网关对外 REST + SSE
 */
import { Hono } from 'hono';
import { streamSSE } from 'hono/streaming';
import type { SessionManager } from './session-manager.js';
import type { GatewayEvent } from '@teletalk/shared';

export function createRoutes(manager: SessionManager): Hono {
  const app = new Hono();

  // —— 状态 ——
  app.get('/api/status', (c) => c.json({
    connected: manager.connected,
    auth: manager.authState,
  }));

  // —— 连接 ——
  app.post('/api/connect', async (c) => {
    try {
      await manager.start();
      return c.json({ ok: true, auth: manager.authState });
    } catch (e) {
      return c.json({ ok: false, error: (e as Error).message }, 400);
    }
  });

  app.post('/api/disconnect', (c) => {
    manager.close();
    return c.json({ ok: true });
  });

  // —— 事件流 ——
  app.get('/api/events', (c) =>
    streamSSE(c, async (stream) => {
      const onEvent = (ev: GatewayEvent) => {
        stream.writeSSE({ event: ev.type, data: JSON.stringify(ev) });
      };
      manager.on('event', onEvent);

      // 心跳保持连接
      const ka = setInterval(() => {
        stream.writeSSE({ event: 'ping', data: String(Date.now()) });
      }, 15_000);

      const cleanup = () => {
        clearInterval(ka);
        manager.off('event', onEvent);
      };

      stream.onAbort(cleanup);
      await new Promise<void>((resolve) => {
        c.req.raw.signal.addEventListener('abort', () => { cleanup(); resolve(); });
      });
    }),
  );

  // —— 扫码登录 ——
  app.post('/api/qrcode', async (c) => {
    try {
      const { QrLoginClient } = await import('../lwp/qr-login.js');
      const cfg = (await import('../config.js')).loadConfig();
      const qr = new QrLoginClient(cfg.dingtalk);
      await qr.connect();
      const result = await qr.requestQrCode();
      qr.close();
      return c.json({ ok: true, qrId: result.qrId, payload: result.payload });
    } catch (e) {
      return c.json({ ok: false, error: (e as Error).message }, 400);
    }
  });

  // —— 离线回放（无凭据时验证用）——
  app.get('/api/replay', async (c) => {
    const dir = c.req.query('dir');
    if (!dir) return c.json({ error: '需要 dir 参数指向抓包目录' }, 400);
    try {
      const { replayMessages } = await import('./mock.js');
      const r = replayMessages(dir);
      return c.json({ frames: r.frames, count: r.messages.length, messages: r.messages });
    } catch (e) {
      return c.json({ error: (e as Error).message }, 400);
    }
  });

  // —— 会话 ——
  app.get('/api/dialogs', async (c) => {
    try {
      const frame = await manager.listDialogs();
      return c.json({ code: frame.code, bytes: frame.body.length, hex: frame.body.toString('hex').slice(0, 400) });
    } catch (e) {
      return c.json({ error: (e as Error).message }, 400);
    }
  });

  app.get('/api/messages/:dialogId', async (c) => {
    const dialogId = c.req.param('dialogId');
    const limit = Number(c.req.query('limit') ?? 20);
    try {
      const frame = await manager.listMessages(dialogId, limit);
      return c.json({ code: frame.code, bytes: frame.body.length, hex: frame.body.toString('hex').slice(0, 800) });
    } catch (e) {
      return c.json({ error: (e as Error).message }, 400);
    }
  });

  app.post('/api/send', async (c) => {
    try {
      const body = await c.req.json<{ cid: string; uid: string; orgId: string; convName: string; text: string }>();
      if (!body.text?.trim()) return c.json({ error: 'text 不能为空' }, 400);
      const frame = await manager.sendText(body);
      return c.json({ ok: frame.code === 200, code: frame.code });
    } catch (e) {
      return c.json({ ok: false, error: (e as Error).message }, 400);
    }
  });

  return app;
}
