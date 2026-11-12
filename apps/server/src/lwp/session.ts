/**
 * 钉钉 LWP 会话
 * 封装鉴权头、注册、同步订阅、消息收发
 */
import { LwpClient } from './client.js';
import { MidGenerator, baseHeaders, type LwpFrame } from './frame.js';
import { extractText } from './message-codec.js';
import { strField, numField, concat, raw, listMessagesBody, listMessagesBodyV1, varint } from './bodies.js';
import { parseDialogDetail, parseLastMessageSnippet, type DialogDetail } from './dialog-parser.js';
import { buildSendBody } from './send-builder.js';
import { getX5Headers, type X5Headers } from './x5-sign.js';

// 抓包验证过的有效游标（服务端拒绝任意值）
export const DEFAULT_CURSOR = 95482;

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
   * 优先用外部注入的值（grab-all 抓到的、与 token 同源），
   * 其次从进程内存扫描（x5-dump.exe）。
   */
  async refreshX5(prefill?: X5Headers): Promise<void> {
    if (prefill?.['x5-sign']) {
      this.x5 = prefill;
      return;
    }
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

  /** 带 x5 签名的头（实测加签名后服务端反而报错，业务请求改走 headers()） */
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

  /** 订阅（需等 600ms 生效，再做业务请求） */
  async sendSubscribe(): Promise<void> {
    this.subscribe();
    await new Promise((r) => setTimeout(r, 2000));
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

  /** 拉取会话列表：listNewest 拿 ID 列表 → 逐个 getById */
  async listDialogs(): Promise<LwpFrame> {
    return this.client.request('/r/Adaptor/IDLOnebox/listNewest', this.headers('p'), Buffer.alloc(0));
  }

  /** 拉取单个会话详情 */
  async getDialog(id: string): Promise<{ detail: DialogDetail; snippet?: string } | null> {
    const body = strField(id);
    const f = await this.client.request('/r/IDLConversation/getById', this.headers('p'), body);
    if (f.code !== 200) return null;
    const detail = parseDialogDetail(f.body, id);
    if (!detail) return null;
    return { detail, snippet: parseLastMessageSnippet(f.body) };
  }

  /**
   * 拉取历史消息。
   *
   * 用 V1（listMessagesPagination）：V2 的字段结构还没吃透（报 Decode parameter error），
   * V1 的 body 与抓包逐字节一致，实测返回 200 + 全部历史消息。
   *
   * 前置条件：必须先 subscribe()（服务端会校验订阅状态）。
   * 首次调用前需 sendSubscribe()（在 reg 之后、业务之前）。
   */
  async listMessages(dialogId: string, limit = 20, cursor = DEFAULT_CURSOR): Promise<LwpFrame> {
    const body = Buffer.concat([
      Buffer.from([0xab]),
      Buffer.from(dialogId, 'latin1'),
      Buffer.from('c2cf', 'hex'),
      Buffer.from('0000019f', 'hex'),
      // 0x61：服务端校验的第 3 参数标记位，挖掉会报 Parameter not found: 4
      Buffer.from([0x61]),
      // 游标：服务端校验具体值（1 / 255 / min_fetch_cursor 都报 Parameter not found）。
      // 抓包里出现过的有效值：95482（最新页）、1778（次页）。
      varint(cursor),
      Buffer.from([0x1d]),
    ]);
    const r = await this.client.request('/r/IDLMessage/listMessagesPagination', this.headers('p'), body);
    return r;
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
