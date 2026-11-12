/**
 * 实测：用内存提取的 token + x5-sign 发起真实 LWP 请求
 *
 * 用法: npx tsx scripts/live-test.ts
 */
import { execFileSync } from 'node:child_process';
import { LwpClient } from '../apps/server/src/lwp/client.js';
import { MidGenerator, baseHeaders } from '../apps/server/src/lwp/frame.js';

const EXE = 'C:/Users/xrl/Codes/teletalk/tools/sign/build/grab-all.exe';

interface Grabbed {
  pid: number;
  token: string;
  did: string;
  x5sign: string;
  orgId: string;
}

console.log('=== 抓取登录态 ===');
const raw = execFileSync(EXE, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
const g = JSON.parse(raw) as Grabbed;
console.log(`  PID:    ${g.pid}`);
console.log(`  did:    ${g.did}`);
console.log(`  token:  ${g.token.slice(0, 40)}... (${g.token.length})`);
console.log(`  x5sign: ${g.x5sign.slice(0, 40)}... (${g.x5sign.length})`);

if (!g.token || !g.did) { console.error('缺少 token 或 did'); process.exit(1); }

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AliApp(DingTalk/9.0.5) com.dingtalk.win/1771550 Channel/';
const APP_KEY = '564ca050be89b14ee78d692f6ded748d';
const APPKEY = '85A09F60A599F5E1867EAB915A8BB07G';

const mid = new MidGenerator();
const client = new LwpClient({ host: 'tls-desktop.dingtalk.com' });

function hdr(signed: boolean): Record<string, string> {
  const h: Record<string, string> = {
    mid: mid.next(),
    did: "bca6f4d9592a54480792269b83c457bb",
    'app-key': APP_KEY,
    appkey: APPKEY,
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
console.log('\n已连接 tls-desktop.dingtalk.com\n');

async function probe(label: string, uri: string, body?: Buffer, signed = true): Promise<void> {
  try {
    const f = await client.request(uri, hdr(signed), body);
    const text = f.body.toString('utf8').replace(/[^\x20-\x7e\u4e00-\u9fa5]/g, '.').slice(0, 80);
    console.log(`  ${label.padEnd(28)} HTTP ${f.code}  ${f.body.length}B  ${text}`);
  } catch (e) {
    console.log(`  ${label.padEnd(28)} 异常 ${(e as Error).message}`);
  }
}

console.log('=== 基础探测 ===');
await probe('/r/Aladdin/lookup', '/r/Aladdin/lookup');
await probe('/r/Aladdin/lookup (无签名)', '/r/Aladdin/lookup', undefined, false);

console.log('\n=== 注册 ===');
await probe('/reg/init', '/reg/init');
await probe('/reg', '/reg');

console.log('\n=== 业务请求 ===');
await probe('会话列表', '/r/Adaptor/IDLOnebox/listNewest',
  Buffer.from([0x00, 0x00, 0x01, 0x04, 0x00, 30]));

client.close();
console.log('\n完成');