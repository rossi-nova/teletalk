/**
 * 抓 token → 关钉钉 → 用 token 连接（避开互踢）
 *
 * 这是工程上的正确做法：钉钉客户端在线时，第三方连接会被踢。
 *
 * 用法: npx tsx scripts/takeover.ts [--close-dingtalk]
 */
import { execFileSync, execSync } from 'node:child_process';
import { LwpClient } from '../apps/server/src/lwp/client.js';
import { MidGenerator } from '../apps/server/src/lwp/frame.js';

const EXE = 'C:/Users/xrl/Codes/teletalk/tools/sign/build/grab-all.exe';
const DID = 'bca6f4d9592a54480792269b83c457bb';
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AliApp(DingTalk/9.0.5) com.dingtalk.win/1771550 Channel/';
const CLOSE = process.argv.includes('--close-dingtalk');

interface Grab { token: string; did: string; x5sign: string; }

function grab(): Grab {
  const raw = execFileSync(EXE, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  return JSON.parse(raw) as Grab;
}

// 1. 抓取
console.log('=== 抓取登录态 ===');
const g = grab();
console.log(`  token:  ${g.token.slice(0, 50)}...`);
console.log(`  x5sign: ${g.x5sign.slice(0, 50)}...`);

if (!g.token) { console.error('未抓到 token'); process.exit(1); }

// 2. 可选：关闭钉钉
if (CLOSE) {
  console.log('\n=== 关闭钉钉（避免互踢）===');
  try {
    execSync('taskkill /IM DingTalk.exe /F', { stdio: 'ignore' });
    console.log('  已关闭');
    await new Promise((r) => setTimeout(r, 3000));
  } catch (e) {
    console.log('  关闭失败（可能已退出）');
  }
}

// 3. 连接
const mid = new MidGenerator();
const client = new LwpClient({ host: 'tls-desktop.dingtalk.com' });

function hdr(): Record<string, string> {
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
  return h;
}

await client.connect();
console.log('\n=== 已连接 ===');

try {
  const reg = await client.request('/reg', hdr());
  console.log(`[/reg] ${reg.code}  ${reg.body.toString('utf8').replace(/[^\x20-\x7e]/g, '.').slice(0, 80)}`);

  await new Promise((r) => setTimeout(r, 300));

  for (const [label, uri, body] of [
    ['listNewest 空', '/r/Adaptor/IDLOnebox/listNewest', Buffer.alloc(0)],
    ['listNewest 1B', '/r/Adaptor/IDLOnebox/listNewest', Buffer.from([0x01])],
    ['lookup', '/r/Aladdin/lookup', undefined],
  ] as Array<[string, string, Buffer | undefined]>) {
    try {
      const f = await client.request(uri, hdr(), body);
      console.log(`[${label}] ${f.code}  ${f.body.length}B  ${f.body.toString('hex').slice(0, 60)}`);
    } catch (e) {
      console.log(`[${label}] 异常 ${(e as Error).message.slice(0, 40)}`);
      break;
    }
  }
} catch (e) {
  console.error('连接异常:', (e as Error).message);
} finally {
  client.close();
}