/**
 * 验证：用从钉钉进程提取的 x5-sign 发起真实 LWP 请求
 *
 * 对比三种情况的服务端响应：
 *   A. 不带 x5 签名
 *   B. 带 x5 签名（进程内缓存的）
 *
 * 用法: npx tsx scripts/verify-x5.ts
 */
import { readFileSync } from 'node:fs';
import { LwpClient } from '../apps/server/src/lwp/client.js';
import { MidGenerator, baseHeaders } from '../apps/server/src/lwp/frame.js';
import { getX5Headers, x5Status } from '../apps/server/src/lwp/x5-sign.js';

// 手动加载 apps/server/.env（避免跨包解析）
try {
  for (const line of readFileSync('apps/server/.env', 'utf8').split('\n')) {
    const m = line.match(/^([A-Z_]+)=(.*)$/);
    if (m && !process.env[m[1]!]) process.env[m[1]!] = m[2]!;
  }
} catch {
  console.error('未找到 apps/server/.env');
}

const deviceId = process.env.DT_DEVICE_ID;
const token = process.env.DT_TOKEN;
const appKey = process.env.DT_APP_KEY;
const appkey = process.env.DT_APPKEY;
const orgId = process.env.DT_ORG_ID;
const ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) DingTalk/9.0.5';

if (!deviceId || !token) {
  console.error('缺少 DT_DEVICE_ID / DT_TOKEN，先跑 tools/capture-login.bat');
  process.exit(1);
}

const status = await x5Status();
console.log('x5 提取状态:', JSON.stringify(status, null, 2));
if (!status.available) {
  console.error('x5-dump.exe 不存在，先编译 tools/sign');
  process.exit(1);
}
if (!status.count) {
  console.error('未提取到 x5-sign。确认钉钉正在运行且已登录');
  process.exit(1);
}

const x5 = await getX5Headers();
console.log('\n使用签名:', x5['x5-sign']?.slice(0, 40) + '...');

const mid = new MidGenerator();
const client = new LwpClient({ host: 'tls-desktop.dingtalk.com' });

function hdr(extra?: Record<string, string>): Record<string, string> {
  return {
    ...baseHeaders({
      mid: mid.next(),
      did: deviceId!,
      appKey: appKey!,
      appkey: appkey!,
      ua,
      orgId,
      token,
      dt: 'p',
    }),
    ...(extra ?? {}),
  };
}

await client.connect();
console.log('\n已连接');

async function tryReq(label: string, extra?: Record<string, string>): Promise<void> {
  try {
    const f = await client.request('/r/Aladdin/lookup', hdr(extra));
    console.log(`  ${label}: HTTP ${f.code}, body ${f.body.length}B`);
    if (f.code !== 200) {
      console.log(`    headers: ${JSON.stringify(f.headers).slice(0, 200)}`);
    }
  } catch (e) {
    console.log(`  ${label}: 异常 ${(e as Error).message}`);
  }
}

console.log('\n对比测试:');
await tryReq('A 无签名');
await tryReq('B 带 x5-sign', x5);

// 业务请求
console.log('\n业务请求（listDialogs）:');
for (const [label, extra] of [['无签名', undefined], ['带签名', x5]] as const) {
  try {
    const f = await client.request(
      '/r/Adaptor/IDLOnebox/listNewest',
      hdr(extra as Record<string, string> | undefined),
      Buffer.from([0x00, 0x00, 0x01, 0x04, 0x00, 30]),
    );
    console.log(`  ${label}: HTTP ${f.code}, body ${f.body.length}B`);
  } catch (e) {
    console.log(`  ${label}: 异常 ${(e as Error).message}`);
  }
}

client.close();
