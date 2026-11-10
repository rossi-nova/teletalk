/**
 * 会话管理器：持有到钉钉的长连接，向 UI 广播事件
 */
import { EventEmitter } from 'node:events';
import { DingtalkSession } from '../lwp/session.js';
import { extractText } from '../lwp/message-codec.js';
import type { Config } from '../config.js';
import type { GatewayEvent, AuthState, Message } from '@teletalk/shared';

export class SessionManager extends EventEmitter {
  private session: DingtalkSession | null = null;
  private auth: AuthState = { loggedIn: false };
  private started = false;

  constructor(private readonly cfg: Config['dingtalk']) {
    super();
  }

  get connected(): boolean {
    return this.session?.client.connected ?? false;
  }

  get authState(): AuthState {
    return this.auth;
  }

  /** 建立连接（幂等） */
  async start(): Promise<void> {
    if (this.started) return;
    if (!this.cfg.deviceId || !this.cfg.token) {
      throw new Error('缺少 DT_DEVICE_ID 或 DT_TOKEN');
    }
    this.started = true;

    const session = new DingtalkSession(this.cfg);
    this.session = session;

    session.client.on('close', () => {
      this.auth = { ...this.auth, loggedIn: false };
      this.broadcast({ type: 'status', auth: this.auth });
      this.started = false;
    });

    session.onMessage((m) => {
      const text = extractText(m.body);
      if (!text) return;
      const msg: Message = {
        id: m.mid,
        dialogId: '',
        senderId: '',
        text,
        createdAt: Date.now(),
        kind: 'text',
        self: false,
      };
      this.broadcast({ type: 'message', message: msg });
    });

    await session.connect();
    await session.lookup();
    await session.regInit();
    const reg = await session.register();
    if (reg.code !== 200) throw new Error(`注册失败: HTTP ${reg.code}`);

    session.subscribe();

    this.auth = {
      loggedIn: true,
      deviceId: this.cfg.deviceId,
      orgId: this.cfg.orgId,
    };
    this.broadcast({ type: 'status', auth: this.auth });

    // 心跳
    setInterval(() => {
      session.heartbeat().catch(() => {});
    }, 42_000).unref();
  }

  requireSession(): DingtalkSession {
    if (!this.session?.client.connected) throw new Error('未连接钉钉');
    return this.session;
  }

  broadcast(ev: GatewayEvent): void {
    this.emit('event', ev);
  }

  close(): void {
    this.session?.close();
    this.session = null;
    this.started = false;
  }
}
