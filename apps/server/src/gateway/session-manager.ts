/**
 * 会话管理器：持有到钉钉的长连接，向 UI 广播事件
 */
import { EventEmitter } from 'node:events';
import { execFileSync, execSync, spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { DingtalkSession } from '../lwp/session.js';
import type { LwpFrame } from '../lwp/frame.js';
import { extractText } from '../lwp/message-codec.js';
import type { Config } from '../config.js';
import type { GatewayEvent, AuthState, Message, Dialog } from '@teletalk/shared';
import { toDialog, extractConvIds, SEED_CONV_IDS } from '../lwp/dialog-parser.js';
import { parseMessagePage } from '../lwp/message-parse.js';

const GRAB_ALL_EXE = resolve(process.cwd(), 'tools/sign/build/grab-all.exe');

interface Grabbed {
  pid: number;
  token: string;
  did: string;
  x5sign: string;
  orgId: string;
}

function grabOnce(): Grabbed | null {
  if (!existsSync(GRAB_ALL_EXE)) return null;
  try {
    const raw = execFileSync(GRAB_ALL_EXE, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 8000 });
    return JSON.parse(raw.trim()) as Grabbed;
  } catch {
    return null;
  }
}

const DINGTALK_EXE = [
  'C:/Program Files (x86)/DingDing/main/current/DingTalk.exe',
  'C:/Program Files (x86)/DingDing/main/current_new/DingTalk.exe',
];

/** 启动钉钉（用于自动获取新鲜登录态） */
function launchDingTalk(): boolean {
  const exe = DINGTALK_EXE.find((x) => existsSync(x));
  if (!exe) return false;
  try {
    spawn(exe, [], { detached: true, stdio: 'ignore', windowsHide: false }).unref();
    return true;
  } catch { return false; }
}

/** 关闭钉钉 */
function killDingTalk(): void {
  try { execSync('taskkill /IM DingTalk.exe /F', { stdio: 'ignore' }); } catch { /* 可能已退出 */ }
}

/**
 * 抓取凭据（带重试）。
 * 钉钉刚启动时 LWP 头尚未构造，did 会抓空——等它连上服务端后再抓。
 */
function grabFromMemory(retries = 6, delayMs = 5000, excludeToken = ''): Grabbed | null {
  for (let i = 0; i < retries; i++) {
    const g = grabOnce();
    if (g?.token && g.did && g.token !== excludeToken) return g;
    console.warn('[grab] 第 ' + (i + 1) + '次未抓全（token=' + (g?.token ? '✓' : '✗') + ' did=' + (g?.did ? '✓' : '✗') + '），' + (i + 1 < retries ? delayMs / 1000 + 's 后重试' : '放弃'));
    if (i + 1 < retries) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, delayMs);
  }
  return grabOnce();
}

function isDingTalkRunning(): boolean {
  try {
    const out = execSync('tasklist /FI "IMAGENAME eq DingTalk.exe" /NH', { encoding: 'utf8', timeout: 5000 });
    return out.includes('DingTalk.exe');
  } catch {
    return false;
  }
}

export class SessionManager extends EventEmitter {
  private session: DingtalkSession | null = null;
  private auth: AuthState = { loggedIn: false };
  private started = false;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private grabbedToken = '';
  private grabbedX5 = '';

  constructor(private readonly cfg: Config['dingtalk']) {
    super();
  }

  get connected(): boolean {
    return this.session?.client.connected ?? false;
  }

  get authState(): AuthState {
    return this.auth;
  }

  /**
   * 建立连接（幂等）。
   *
   * 启动流程：
   *   1. 检查钉钉是否运行（否则 grab-all.exe 无源头可抓）
   *   2. 从钉钉进程内存提取 token + did + x5-sign
   *   3. 用提取到的凭据发起 LWP 连接
   */
  async start(): Promise<void> {
    if (this.started) return;

    // —— 确保钉钉在线（离线时自动拉起，等待它建立连接并生成新鲜 token） ——
    if (!isDingTalkRunning()) {
      console.warn('[launch] 钉钉未运行，正在启动…（需已扫码登录过，自动登录约 30 秒）');
      if (!launchDingTalk()) throw new Error('找不到 DingTalk.exe，请手动启动钉钉');
    }

    // —— 从钉钉进程内存抓取凭据 ——
    if (!this.cfg.token) {
      const g = grabFromMemory(24, 5000);
      if (!g?.token) {
        throw new Error(
          '未能从钉钉进程提取 token。请确认：\n' +
          '  1. 钉钉已完成扫码登录\n' +
          '  2. ' + GRAB_ALL_EXE + ' 存在（需先编译 tools/sign/）'
        );
      }
      this.cfg.token = g.token;
      this.grabbedToken = g.token;
      this.grabbedX5 = g.x5sign;
      if (g.did && !this.cfg.deviceId) this.cfg.deviceId = g.did;
      if (g.orgId) this.cfg.orgId = g.orgId;
      if (g.x5sign) {
        console.warn('[grab] token=' + g.token.slice(0, 30) + '... x5-sign=' + g.x5sign.slice(0, 20) + '...  did=' + g.did);
      }
    }

    if (!this.cfg.deviceId || !this.cfg.token) {
      throw new Error('缺少 DT_DEVICE_ID 或 DT_TOKEN（从内存提取也失败了）');
    }

    // —— 互踢约束：钉钉客户端与网关不能同时在线 ——
    // （关闭动作移到 /reg 验证成功之后，保证 token 新鲜时才杀）
    if (isDingTalkRunning() && !this.cfg.autoClose) {
      console.warn('');
      console.warn('⚠ 钉钉客户端仍在运行：/reg 成功后服务端会断开本连接（多客户端互踢）。');
      console.warn('  两种解法：');
      console.warn('    1. 设 DT_AUTO_CLOSE=1 —— 网关验证通过后自动关钉钉并重连');
      console.warn('    2. 手动 taskkill /IM DingTalk.exe /F 后重连');
      console.warn('');
    }

    this.started = true;
    try {

    const session = new DingtalkSession(this.cfg);
    this.session = session;

    // 注入 grab-all 抓到的 x5-sign（与 token 同源，避免二次扫描）
    await session.refreshX5(this.grabbedX5 ? {
      'x5-sign': this.grabbedX5,
      'x5-bx-version': 'pc_1.0.70.1028_0',
      'x5-sgext': 'win_reserve',
    } : undefined).catch(() => {});

    this.attachListeners(session);

    await session.connect();
    await session.lookup();
    await session.regInit();
    let reg = await session.register();
    // 401 自愈：token 过期则重抓凭据重试（token 每次钉钉重启都会轮换）
    for (let attempt = 1; reg.code === 401 && attempt <= 2; attempt++) {
      console.warn('[/reg 401] token 过期，重抓凭据（第 ' + attempt + ' 次）…');
      session.close();
      this.session = null;
      const old: string | undefined = this.cfg.token;
      const g = grabFromMemory(3, 4000);
      if (g?.token && g.token !== old) {
        this.cfg.token = g.token;
        this.grabbedToken = g.token;
        this.grabbedX5 = g.x5sign;
        if (g.did) this.cfg.deviceId = g.did;
        console.warn('[regrab] 新 token ' + g.token.slice(0, 24) + '…');
      }
      const s2 = new DingtalkSession(this.cfg);
      this.session = s2;
      this.attachListeners(s2);
      await s2.refreshX5(this.grabbedX5 ? {
        'x5-sign': this.grabbedX5,
        'x5-bx-version': 'pc_1.0.70.1028_0',
        'x5-sgext': 'win_reserve',
      } : undefined).catch(() => {});
      await s2.connect();
      await s2.lookup();
      await s2.regInit();
      reg = await s2.register();
    }
    console.warn('[/reg 响应]', 'code=' + reg.code, 'bytes=' + reg.body.length, JSON.stringify(reg.body.toString('utf8').slice(0, 200)));
    if (reg.code !== 200) throw new Error(`注册失败: HTTP ${reg.code}`);

    // —— token 已验证：关闭钉钉（避免互踢），再用已验证凭据重连 ——
    if (this.cfg.autoClose && isDingTalkRunning()) {
      console.warn('[auto-close] 关闭钉钉客户端（token 已验证）…');
      try {
        execSync('taskkill /IM DingTalk.exe /F', { stdio: 'ignore' });
        await new Promise((r) => setTimeout(r, 3000));
        console.warn('[auto-close] 已关闭，重连…');
      } catch {
        console.warn('[auto-close] 关闭失败（可能已退出）');
      }
      session.close();
      this.session = null;
      const s3 = new DingtalkSession(this.cfg);
      this.session = s3;
      this.attachListeners(s3);
      await s3.refreshX5(this.grabbedX5 ? {
        'x5-sign': this.grabbedX5,
        'x5-bx-version': 'pc_1.0.70.1028_0',
        'x5-sgext': 'win_reserve',
      } : undefined).catch(() => {});
      await s3.connect();
      await s3.lookup();
      await s3.regInit();
      const reg2 = await s3.register();
      console.warn('[/reg 重连]', 'code=' + reg2.code);
      if (reg2.code !== 200) throw new Error(`重连注册失败: HTTP ${reg2.code}`);
      // 服务端清理旧连接需要几百毫秒，过早订阅会被踢
      await new Promise((r) => setTimeout(r, 2500));
    }

    // 订阅后稍等，订阅状态才在服务端生效（否则 listMessages 报 Parameter not found）
    await this.session!.sendSubscribe();

    this.auth = {
      loggedIn: true,
      deviceId: this.cfg.deviceId,
      orgId: this.cfg.orgId,
    };
    this.broadcast({ type: 'status', auth: this.auth });

    // 心跳
    const hbSession = this.session!;
    this.heartbeatTimer = setInterval(() => {
      hbSession.heartbeat().catch(() => {});
    }, 42_000).unref();
    } catch (e) {
      this.started = false;
      this.session?.close();
      this.session = null;
      throw e;
    }
  }


  /** 挂连接事件监听（自愈重建会话时复用） */
  private attachListeners(session: DingtalkSession): void {
    session.client.on('raw-close', (info: unknown) => {
      console.warn('[连接关闭]', JSON.stringify(info));
      if (this.auth.loggedIn) console.warn('  ↳ 若发生在 /reg 成功后，是钉钉客户端在线导致的互踢。');
    });
    session.client.on('raw-end', () => console.warn('[对端结束]'));
    session.client.on('error', (e: Error) => console.warn('[连接错误]', e.message));
    session.client.on('close', () => {
      this.auth = { ...this.auth, loggedIn: false };
      this.broadcast({ type: 'status', auth: this.auth });
      this.started = false;
      if (this.heartbeatTimer) { clearInterval(this.heartbeatTimer); this.heartbeatTimer = null; }
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
  }
  async sendText(params: { cid: string; text: string; uid?: string; orgId?: string; convName?: string }) {
    return this.requireSession().sendText(params);
  }

  /** 会话列表：listNewest 拿 ID → 逐个 getById */
  async listDialogs(): Promise<Dialog[]> {
    const s = this.requireSession();
    const frame = await s.listDialogs();
    if (frame.code !== 200) return [];
    // listNewest 返回 ID 列表或空数组（0xC0）
    const ids = extractConvIds(frame.body);
    // Onebox 的 listNewest 不返回会话列表（抓包里它当时也是 0xC0 空），
    // 用抓包验证过的种子 ID 兜底，逐个 getById 拉详情。
    const useIds = ids.length ? ids : SEED_CONV_IDS;
    const out: Dialog[] = [];
    for (const id of useIds) {
      try {
        const r = await s.getDialog(id);
        if (r) out.push(toDialog(r.detail));
      } catch (e) { console.warn('[getDialog]', id, (e as Error).message); }
    }
    return out;
  }

  /** 直接按 ID 拉会话（listNewest 为空时的回退） */
  async getDialogs(ids: string[]): Promise<Dialog[]> {
    const s = this.requireSession();
    const out: Dialog[] = [];
    for (const id of ids) {
      try {
        const r = await s.getDialog(id);
        if (r) out.push(toDialog(r.detail));
        else console.warn('[getDialog]', id, '解析失败或非 200');
      } catch (e) { console.warn('[getDialog]', id, (e as Error).message); }
    }
    return out;
  }

  async listMessages(dialogId: string, limit?: number): Promise<Message[]> {
    const s = this.requireSession();
    const frame = await s.listMessages(dialogId, limit ?? 20);
    if (frame.code !== 200) return [];
    return s.fillSenders(parseMessagePage(frame.body, dialogId));
  }

  requireSession(): DingtalkSession {
    if (!this.session?.client.connected) throw new Error('未连接钉钉');
    return this.session;
  }

  broadcast(ev: GatewayEvent): void {
    this.emit('event', ev);
  }

  close(): void {
    if (this.heartbeatTimer) { clearInterval(this.heartbeatTimer); this.heartbeatTimer = null; }
    this.session?.close();
    this.session = null;
    this.started = false;
  }
}
