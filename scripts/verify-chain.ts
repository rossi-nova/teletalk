/**
 * x5 签名链路验证器
 *
 * 验证「从钉钉进程提取的 x5-sign 是否可用于 LWP 请求」。
 *
 * 由于 token 可能过期，本工具先用抓包/环境里的 token 做一次鉴权探测，
 * 再对比带/不带 x5 头的响应差异。
 *
 * 用法:
 *   npx tsx scripts/verify-chain.ts            # 完整验证
 *   npx tsx scripts/verify-chain.ts --dump     # 只打印当前提取到的签名
 */
import { readFileSync } from 'node:fs';
import { LwpClient } from '../apps/server/src/lwp/client.js';
import { MidGenerator, baseHeaders } from '../apps/server/src/lwp/frame.js';
import { readX5Signs, x5Status } from '../apps/server/src/lwp/x5-sign.js';

// 加载 .env
try {
  for (const line of readFileSync('apps/server/.env', 'utf8').split('\n')) {
    const m = line.match(/^([A-Z_]+)=(.*)$/);
    if (m && !process.env[m[1]!]) process.env[m[1]!] = m[2]!;
  }
} catch { /* 忽略 */ }

const dumpOnly = process.argv.includes('--dump');

const status = await x5Status();
console.log('=== x5 提取状态 ===');
console.log(JSON.stringify(status, null, 2));

if (dumpOnly) process.exit(status.count ? 0 : 1);

if (!status.available) {
  console.error('\n✗ x5-dump.exe 不存在');
  process.exit(1);
}
if (!status.count) {
  console.error('\n✗ 未提取到 x5-sign（钉钉未运行或未登录）');
  process.exit(1);
}

const tokens = await readX5Signs();
const deviceId = process.env.DT_DEVICE_ID;
const token = process.env.DT_TOKEN;

console.log(`\n=== 环境 ===`);
console.log(`  设备 ID: ${deviceId ?? '(无)'}`);
console.log(`  Token:   ${token ? token.slice(0, 30) + '...' : '(无)'}`);

if (!deviceId || !token) {
  console.log('\n✗ 缺少设备 ID 或 Token，跳过请求验证');
  process.exit(2);
}

const mid = new MidGenerator();
const client = new LwpClient({ host: 'tls-desktop.dingtalk.com' });

function hdr(signed: boolean): Record<string, string> {
  const base = baseHeaders({
    mid: mid.next(),
    did: deviceId!,
    appKey: process.env.DT_APP_KEY!,
    appkey: process.env.DT_APPKEY!,
    ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) DingTalk/9.0.5',
    orgId: process.env.DT_ORG_ID,
    token,
    dt: 'p',
  });
  if (!signed) return base;
  return {
    ...base,
    'x5-sign': tokens[0]!.value,
    'x5-bx-version': 'pc_1.0.70.1028_0',
    'x5-sgext': 'win_reserve',
  };
}

await client.connect();
console.log('\n已连接\n');

console.log('=== 对比测试 ===');
for (const signed of [false, true]) {
  const label = signed ? '带 x5-sign' : '无签名   ';
  try {
    const f = await client.request('/r/Aladdin/lookup', hdr(signed));
    console.log(`  ${label}: HTTP ${f.code}  body=${f.body.length}B`);
    if (f.code >= 400) {
      const preview = f.body.toString('utf8').replace(/[^\x20-\x7e一-龥]/g, '.').slice(0, 100);
      if (preview.trim()) console.log(`     body: ${preview}`);
    }
  } catch (e) {
    console.log(`  ${label}: 异常 ${(e as Error).message}`);
  }
}

client.close();

console.log('\n=== 结论 ===');
console.log('若「带 x5-sign」与「无签名」的响应码不同，说明签名被服务端校验。');
console.log('若两者相同（如都为 401/500），说明卡在更早的鉴权层（token 无效）。');
