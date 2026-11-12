/**
 * 会话已建立后，逐个探测业务接口
 *
 * /reg 已成功（200，路由 HZ），说明鉴权+签名链路通。
 * 现在找哪些业务接口可用，以及 500 的原因。
 *
 * 用法: npx tsx scripts/probe-apis.ts
 */
import { execFileSync } from 'node:child_process';
import { LwpClient } from '../apps/server/src/lwp/client.js';
import { MidGenerator } from '../apps/server/src/lwp/frame.js';

const EXE = 'C:/Users/xrl/Codes/teletalk/tools/sign/build/grab-all.exe';
const g = JSON.parse(execFileSync(EXE, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim()) as {
  pid: number; token: string; did: string; x5sign: string;
};

const DID = 'bca6f4d9592a54480792269b83c457bb';  // 内存中确认的真实设备 ID
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AliApp(DingTalk/9.0.5) com.dingtalk.win/1771550 Channel/';

const mid = new MidGenerator();
const client = new LwpClient({ host: 'tls-desktop.dingtalk.com' });

function hdr(signed = true): Record<string, string> {
  const h: Record<string, string> = {
    mid: mid.next(),
    did: DID,
    'app-key': '564ca050be89b14ee78d692f6ded748d',
    appkey: '85A09F60A599F5E1867EAB915A8BB07G',
    ua: UA,
    token: g.token,
    dt: 'p',
  };
  if (signed && g.x5sign) {
    h['x5-sign'] = g.x5sign;
    h['x5-bx-version'] = 'pc_1.0.70.1028_0';
    h['x5-sgext'] = 'win_reserve';
  }
  return h;
}

await client.connect();
console.log('已连接\n');

// 1. 先注册
const reg = await client.request('/reg', hdr());
console.log(`/reg → ${reg.code}  ${reg.body.toString('utf8').slice(0, 100)}`);
const route = reg.headers['auth-route-logic-unit'] ?? reg.headers['auth-route-unit'];
console.log(`路由: ${route}\n`);

async function probe(label: string, uri: string, body?: Buffer): Promise<void> {
  try {
    const f = await client.request(uri, hdr(), body);
    const txt = f.body.toString('utf8').replace(/[^\x20-\x7e\u4e00-\u9fa5]/g, '.').slice(0, 70);
    console.log(`  ${label.padEnd(30)} ${String(f.code).padStart(3)}  ${String(f.body.length).padStart(4)}B  ${txt}`);
  } catch (e) {
    console.log(`  ${label.padEnd(30)} ERR  ${(e as Error).message.slice(0, 50)}`);
  }
}

console.log('=== 无 body 的接口 ===');
await probe('/r/Aladdin/lookup', '/r/Aladdin/lookup');
await probe('/reg/init', '/reg/init');

console.log('\n=== 带 body 的接口（试各种长度）===');
for (const len of [0, 1, 2, 4, 8, 16]) {
  const body = Buffer.alloc(len, 0);
  await probe(`listNewest body=${len}B`, '/r/Adaptor/IDLOnebox/listNewest', body);
}

console.log('\n=== 从旧抓包提取的真实 body ===');
// 旧抓包里 listNewest 的 body
const sample = Buffer.from([0x00, 0x00, 0x01, 0x04, 0x00, 30]);
await probe('listNewest (旧样本)', '/r/Adaptor/IDLOnebox/listNewest', sample);

client.close();