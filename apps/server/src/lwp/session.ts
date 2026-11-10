/**
 * 钉钉 LWP 会话
 * 封装鉴权头、注册、同步订阅、消息收发
 */
import { LwpClient } from './client.js';
import { MidGenerator, baseHeaders, type LwpFrame } from './frame.js';
import { extractText } from './message-codec.js';
import { strId, numField, concat } from './bodies.js';
import { buildSendBody } from './send-builder.js';

export interface SessionConfig {
  host?: string;
  deviceId: string;
  appKey: string;
  appkey: string;
  ua: string;
  token?: string;
  orgId?: string;
}

export interface RawMessage {
  mid: string;
  uri: string;
  body: Buffer;
}

export class DingtalkSession {
  readonly client: LwpClient;
  private mid = new MidGenerator();
  private orgId?: string;

  constructor(private readonly cfg: SessionConfig) {
    this.client = new LwpClient({ host: cfg.host ?? 'tls-desktop.dingtalk.com' });
    this.orgId = cfg.orgId;
  }

  private headers(dt?: 'p' | 'j'): Record<string, string> {
    return baseHeaders({
      mid: this.mid.next(),
      did: this.cfg.deviceId,
      appKey: this.cfg.appKey,
      appkey: this.cfg.appkey,
      ua: this.cfg.ua,
      orgId: this.orgId,
      token: this.cfg.token,
      dt,
    });
  }

  async connect(): Promise<void> {
    await this.client.connect();
    this.client.on('frame', (f: LwpFrame) => this.onPush(f));
  }

  /** 服务发现 */
  async lookup(): Promise<LwpFrame> {
    return this.client.request('/r/Aladdin/lookup', this.headers());
  }

  /** 初始化长连接 */
  async regInit(): Promise<LwpFrame> {
    return this.client.request('/reg/init', this.headers());
  }

  /** 用 token 注册（鉴权入口） */
  async register(): Promise<LwpFrame> {
    if (!this.cfg.token) throw new Error('缺少 token，需先登录');
    return this.client.request('/reg', this.headers());
  }

  /** 订阅消息推送 */
  subscribe(): void {
    for (const uri of ['/s/sync', '/s/synca', '/s/feynman']) {
      this.client.fire(uri, this.headers());
    }
  }

  /** 设置组织 */
  setOrg(orgId: string): void {
    this.orgId = orgId;
  }

  /** 拉取会话列表（请求体格式待补外层长度） */
  async listDialogs(): Promise<LwpFrame> {
    const body = numField([0x00, 0x00, 0x01, 0x04, 0x00, 30]);
    return this.client.request('/r/Adaptor/IDLOnebox/listNewest', this.headers('p'), body);
  }

  /** 拉取历史消息（cursor 传 0 取最新一页） */
  async listMessages(dialogId: string, limit = 20): Promise<LwpFrame> {
    const body = concat(strId(dialogId), numField([0x00, 0x00, 0x01]), Buffer.from([limit]));
    return this.client.request('/r/IDLMessage/listMessagesPaginationV2', this.headers('p'), body);
  }

  /** 已读回执 */
  async markRead(dialogId: string): Promise<LwpFrame> {
    return this.client.request('/r/IDLMessageStatus/updateToReadV2', this.headers('p'));
  }

  /** 发送文本消息 */
  async sendText(params: { cid: string; uid: string; orgId: string; convName: string; text: string }): Promise<LwpFrame> {
    const body = buildSendBody(params);
    return this.client.request('/r/IDLSend/send', this.headers('p'), body);
  }

  /** 心跳 */
  async heartbeat(): Promise<void> {
    this.client.fire('/r/Adaptor/TangleNetworkSession/heartbeat', this.headers('p'), Buffer.from([0x81, 0x03, 0x90]));
  }

  private onPush(frame: LwpFrame): void {
    // 推送帧：code=200 但无对应 inflight 的请求
    this.emitMessage({ mid: frame.headers.mid ?? '', uri: '', body: frame.body });
  }

  private listeners: Array<(m: RawMessage) => void> = [];
  onMessage(fn: (m: RawMessage) => void): void {
    this.listeners.push(fn);
  }
  private emitMessage(m: RawMessage): void {
    for (const fn of this.listeners) fn(m);
  }

  /** 从推送 body 提取文本（容错） */
  static textOf(frame: LwpFrame): string | null {
    try {
      return extractText(frame.body);
    } catch {
      return null;
    }
  }

  close(): void {
    this.client.close();
  }
}
