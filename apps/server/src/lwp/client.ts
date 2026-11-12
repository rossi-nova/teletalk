/**
 * LWP 长连接客户端
 * TLS → 帧流 → 请求/响应配对
 */
import tls from 'node:tls';
import { EventEmitter } from 'node:events';
import { parseFrames, encodeRequest, type LwpFrame } from './frame.js';
import { maybeGunzip } from './decompress.js';

export interface LwpClientOptions {
  host: string;
  port?: number;
  timeoutMs?: number;
  /** 连接后是否发 hello（部分端点需要），暂时留空 */
  onFrame?: (frame: LwpFrame) => void;
}

export class LwpClient extends EventEmitter {
  private socket: tls.TLSSocket | null = null;
  private pending: Buffer = Buffer.alloc(0);
  private inflight = new Map<string, { resolve: (f: LwpFrame) => void; reject: (e: Error) => void; timer: NodeJS.Timeout }>();
  private closed = false;

  constructor(private readonly opts: LwpClientOptions) {
    super();
  }

  get connected(): boolean {
    return this.socket !== null && !this.closed;
  }

  async connect(): Promise<void> {
    const { host, port = 443, timeoutMs = 15000 } = this.opts;
    return new Promise((resolve, reject) => {
      const socket = tls.connect({ host, port, servername: host, rejectUnauthorized: false });

      const timer = setTimeout(() => {
        socket.destroy();
        reject(new Error(`连接超时: ${host}:${port}`));
      }, timeoutMs);

      socket.once('secureConnect', () => {
        clearTimeout(timer);
        this.socket = socket;
        this.closed = false;
        socket.on('data', (chunk) => this.onData(chunk));
        socket.on('close', (hadError) => { this.emit('raw-close', { hadError }); this.onClose(); });
        socket.on('error', (e) => this.emit('error', e));
        socket.on('end', () => this.emit('raw-end'));
        this.emit('connect');
        resolve();
      });

      socket.once('error', (e) => {
        clearTimeout(timer);
        reject(e);
      });
    });
  }

  private onData(chunk: Buffer): void {
    this.pending = Buffer.concat([this.pending, chunk]);
    const { frames, rest } = parseFrames(this.pending);
    this.pending = rest;
    for (const f of frames) this.dispatch(f);
  }

  private dispatch(frame: LwpFrame): void {
    // 大响应 gzip 压缩，统一解压
    if (frame.kind === 'res' && frame.body.length > 3) {
      frame = { ...frame, body: maybeGunzip(frame.body) };
    }
    if (frame.kind === 'res') {
      const mid = frame.headers.mid;
      if (mid) {
        const p = this.inflight.get(mid);
        if (p) {
          clearTimeout(p.timer);
          this.inflight.delete(mid);
          p.resolve(frame);
          return;
        }
      }
    }
    this.emit('frame', frame);
  }

  private onClose(): void {
    this.closed = true;
    this.socket = null;
    for (const [mid, p] of this.inflight) {
      clearTimeout(p.timer);
      p.reject(new Error(`连接关闭，未收到响应: ${mid}`));
    }
    this.inflight.clear();
    this.emit('close');
  }

  /** 发送请求并等待同 mid 的响应 */
  request(uri: string, headers: Record<string, string>, body?: Buffer, timeoutMs = 15000): Promise<LwpFrame> {
    if (!this.socket) return Promise.reject(new Error('未连接'));
    const mid = headers.mid;
    if (!mid) return Promise.reject(new Error('缺少 mid'));

    const packet = encodeRequest(uri, headers, body);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.inflight.delete(mid);
        reject(new Error(`请求超时: ${uri}`));
      }, timeoutMs);

      this.inflight.set(mid, { resolve, reject, timer });
      this.socket!.write(packet);
      this.emit('sent', uri, body?.length ?? 0);
    });
  }

  /** 只发不等待（订阅类） */
  fire(uri: string, headers: Record<string, string>, body?: Buffer): void {
    if (!this.socket) throw new Error('未连接');
    this.socket.write(encodeRequest(uri, headers, body));
  }

  close(): void {
    this.socket?.end();
    this.closed = true;
  }
}
