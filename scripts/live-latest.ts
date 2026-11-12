/**
 * 实时抓取 + 即时使用（token 生命周期很短）
 *
 * 关键：每次请求前都重新从内存取 token，避免用到过期的。
 *
 * 用法: npx tsx scripts/live-latest.ts
 */
import { execFileSync } from 'node:child_process';
import { LwpClient } from '../apps/server/src/lwp/client.js';
import { MidGenerator } from '../apps/server/src/lwp/frame.js';

const EXE = 'C:/Users/xrl/Codes/teletalk/tools/sign/build/grab-all.exe';
const DID = 'bca6f4d9592a54480792269b83c457bb';
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AliApp(DingTalk/9.0.5) com.dingtalk.win/1771550 Channel/';

interface Grab { token: string; did: string; x5sign: string; }

function grab(): Grab {
  const raw = execFileSync(EXE, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  return JSON.parse(raw) as Grab;
}

const mid = new MidGenerator();
const client = new LwpClient({ host: 'tls-desktop.dingtalk.com' });
await client.connect();
console.log('已连接\n');

/** 每次都重新抓 token */
async function call(uri: string, body?: Buffer): Promise<{ code: number; body: Buffer; hdr: Record<string, string> }> {
  const g = grab();
  const h: Record<string, string> = {
    mid: mid.next(),
    did: DID,
    'app-key': '564ca050be89b14ee78d692f6ded748d',
    appkey: '85A09F60A599F5E1867EAB915A8BB07G',
    ua: UA,
    token: g.token,
    dt: 'p',
  };
  if (g.x5sign) {
    h['x5-sign'] = g.x5sign;
    h['x5-bx-version'] = 'pc_1.0.70.1028_0';
    h['x5-sgext'] = 'win_reserve';
  }
  const f = await client.request(uri, h, body);
  return { code: f.code, body: f.body, hdr: f.headers };
}

// 1. reg
for (let attempt = 1; attempt <= 3; attempt++) {
  const r = await call('/reg');
  const txt = r.body.toString('utf8').replace(/[^\x20-\x7e]/g, '.');
  console.log(`[/reg 第${attempt}次] ${r.code}  ${txt.slice(0, 90)}`);
  if (r.code === 200) break;
  await new Promise((res) => setTimeout(res, 1000));
}

// 2. 会话列表（用旧抓包的正确 body 结构）
console.log('\n=== 会话列表 ===');
const bodies: Array<[string, Buffer]> = [
  ['空', Buffer.alloc(0)],
  ['1B 0x01', Buffer.from([0x01])],
  ['旧样本', Buffer.from([0x00, 0x00, 0x01, 0x04, 0x00, 30])],
];

for (const [label, body] of bodies) {
  const r = await call('/r/Adaptor/IDLOnebox/listNewest', body);
  const txt = r.body.toString('utf8').replace(/[^\x20-\x7e\u4e00-\u9fa5]/g, '.').slice(0, 60);
  console.log(`  ${label.padEnd(12)} ${r.code}  ${r.body.length}B  ${txt}`);
  if (r.code === 200 && r.body.length > 2) {
    console.log(`    hex: ${r.body.toString('hex').slice(0, 120)}`);
  }
}

client.close();