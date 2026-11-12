/**
 * 最终验证：完整的「抓 token → 接管连接 → 拉会话」闭环
 */
import { execFileSync } from 'node:child_process';
import { LwpClient } from '../apps/server/src/lwp/client.js';
import { MidGenerator } from '../apps/server/src/lwp/frame.js';

const EXE = 'C:/Users/xrl/Codes/teletalk/tools/sign/build/grab-all.exe';
const DID = 'bca6f4d9592a54480792269b83c457bb';
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AliApp(DingTalk/9.0.5) com.dingtalk.win/1771550 Channel/';

const g = JSON.parse(execFileSync(EXE, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim()) as {
  token: string; did: string; x5sign: string;
};

console.log('token:', g.token.slice(0, 60) + '...');
console.log('x5-sign:', g.x5sign.slice(0, 60) + '...');

const mid = new MidGenerator();
const c = new LwpClient({ host: 'tls-desktop.dingtalk.com' });

await c.connect();

const h: Record<string, string> = {
  mid: mid.next(),
  did: DID,
  'app-key': '564ca050be89b14ee78d692f6ded748d',
  appkey: '85A09F60A599F5E1867EAB915A8BB07G',
  ua: UA,
  token: g.token,
  dt: 'p',
  'x5-sign': g.x5sign,
  'x5-bx-version': 'pc_1.0.70.1028_0',
  'x5-sgext': 'win_reserve',
};

const reg = await c.request('/reg', h);
console.log(`\n/reg:   ${reg.code}  ${reg.body.length}B`);
console.log(`路由:    ${reg.headers['auth-route-logic-unit']}`);
console.log(`headers: ${JSON.stringify(reg.headers).slice(0, 150)}\n`);

// 试各种业务接口
for (const [label, uri, body] of [
  ['listNewest', '/r/Adaptor/IDLOnebox/listNewest', Buffer.from([0x01])],
  ['listMessages', '/r/IDLMessage/listMessagesPaginationV2', Buffer.alloc(16, 0)],
  ['heartbeat', '/r/Adaptor/TangleNetworkSession/heartbeat', Buffer.from([0x81, 0x03, 0x90])],
]) {
  h.mid = mid.next();
  try {
    const f = await c.request(uri, h, body);
    const txt = f.body.toString('utf8').replace(/[^\x20-\x7e]/g, '.').slice(0, 60);
    console.log(`[${label}]  ${f.code}  ${f.body.length}B  ${txt}`);
  } catch (e) {
    console.log(`[${label}]  ERR ${(e as Error).message.slice(0, 40)}`);
  }
}

c.close();
console.log('\n✓ 闭环验证完成');