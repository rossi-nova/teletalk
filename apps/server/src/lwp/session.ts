/**
 * 钉钉 LWP 会话
 * 封装鉴权头、注册、同步订阅、消息收发
 */
import { LwpClient } from './client.js';
import { MidGenerator, baseHeaders, type LwpFrame } from './frame.js';
import { extractText } from './message-codec.js';
import { strId, numField, concat } from './bodies.js';
import { buildSendBody } from './send-builder.js';
import { getX5Headers, type X5Headers } from './x5-sign.js';

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
  /** 缓存的 x5 签名头（钉钉进程内生成的副本） */
  private x5: X5Headers = {};

  constructor(private readonly cfg: SessionConfig) {
    this.client = new LwpClient({ host: cfg.host ?? 'tls-desktop.dingtalk.com' });
    this.orgId = cfg.orgId;
  }

  /**
   * 刷新 x5 头。
   * 签名由 SecurityGuardSDK64.dll 在钉钉进程内生成，这里从进程内存读取。
   * 失败时保持空，请求仍会发出（服务端可能拒绝）。
   */
  async refreshX5(): Promise<void> {
    try {
      this.x5 = await getX5Headers();
    } catch {
      this.x5 = {};
    }
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

  /** 带 x5 签名的头（业务请求用） */
  private signedHeaders(dt?: 'p' | 'j'): Record<string, string> {
    return { ...this.headers(dt), ...this.x5 };
  }

  async connect(): Promise<void> {
    await this.refreshX5();
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
    return this.client.request('/r/Adaptor/IDLOnebox/listNewest', this.signedHeaders('p'), body);
  }

  /** 拉取历史消息（cursor 传 0 取最新一页） */
  async listMessages(dialogId: string, limit = 20): Promise<LwpFrame> {
    const body = concat(strId(dialogId), numField([0x00, 0x00, 0x01]), Buffer.from([limit]));
    return this.client.request('/r/IDLMessage/listMessagesPaginationV2', this.signedHeaders('p'), body);
  }

  /** 已读回执 */
  async markRead(dialogId: string): Promise<LwpFrame> {
    return this.client.request('/r/IDLMessageStatus/updateToReadV2', this.signedHeaders('p'));
  }

  /** 发送文本消息 */
  async sendText(params: { cid: string; uid: string; orgId: string; convName: string; text: string }): Promise<LwpFrame> {
    const body = buildSendBody(params);
    return this.client.request('/r/IDLSend/send', this.signedHeaders('p'), body);
  }

  /** 心跳 */
  async heartbeat(): Promise<void> {
    this.client.fire('/r/Adaptor/TangleNetworkSession/heartbeat', this.signedHeaders('p'), Buffer.from([0x81, 0x03, 0x90]));
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
