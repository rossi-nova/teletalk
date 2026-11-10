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

  // —— 占位：需协议字段补齐后启用 ——
  app.get('/api/dialogs', (c) => c.json({ error: '待实现：需补齐 listNewestExtV4 的请求体' }, 501));
  app.get('/api/messages/:dialogId', (c) => c.json({ error: '待实现：需补齐 listMessagesPaginationV2 的请求体' }, 501));
  app.post('/api/send', (c) => c.json({ error: '待实现：需补齐 IDLSend 的请求体构造' }, 501));

  return app;
}
