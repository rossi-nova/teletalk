/**
 * 扫码登录：获取二维码与状态轮询（前半段，无需签名）
 *
 * 已确认协议：
 *   generateForConfirmLogin → 返回 "lwpqr_<UUID>"
 *   pushConfirmLogin       → 提交扫码结果（需要 oauth_k1 token）
 *   loginByFido            → 换取登录 token（需要 x5-sign 签名）
 *
 * 本模块实现第 1 步，第 2/3 步依赖真实客户端或签名逆向。
 */
import { LwpClient } from './client.js';
import { MidGenerator, baseHeaders } from './frame.js';

export interface QrCodeRequest {
  deviceId: string;
  appKey: string;
  appkey: string;
  ua: string;
  host?: string;
}

export interface QrCodeResult {
  /** 形如 lwpqr_2A660AC1-3799-4E41-A850-693463F16007 */
  qrId: string;
  /** 可编码为二维码的字符串 */
  payload: string;
}

export class QrLoginClient {
  private client: LwpClient;
  private mid = new MidGenerator();

  constructor(private readonly cfg: QrCodeRequest) {
    this.client = new LwpClient({ host: cfg.host ?? 'tls-desktop.dingtalk.com' });
  }

  private headers(dt?: 'p' | 'j'): Record<string, string> {
    return baseHeaders({
      mid: this.mid.next(),
      did: this.cfg.deviceId,
      appKey: this.cfg.appKey,
      appkey: this.cfg.appkey,
      ua: this.cfg.ua,
      dt,
    });
  }

  async connect(): Promise<void> {
    await this.client.connect();
  }

  /**
   * 申请二维码
   * 请求体：da 00 58 + <58 字节的客户端标识>
   */
  async requestQrCode(): Promise<QrCodeResult> {
    // 实测请求体：da 00 58 后跟 88 字节 payload（含设备指纹等）
    // 这里用固定长度占位，真实值需从配置注入
    const payload = Buffer.alloc(88, 0);
    const body = Buffer.concat([Buffer.from([0xda, 0x00, 0x58]), payload]);

    const frame = await this.client.request('/r/Adaptor/QrcodeI/generateForConfirmLogin', this.headers('p'), body);
    if (frame.code !== 200) throw new Error(`获取二维码失败: HTTP ${frame.code}`);

    const qrId = frame.body.toString('utf8').trim();
    if (!qrId.startsWith('lwpqr_')) throw new Error(`响应格式异常: ${qrId.slice(0, 30)}`);

    return { qrId, payload: qrId };
  }

  close(): void {
    this.client.close();
  }
}
