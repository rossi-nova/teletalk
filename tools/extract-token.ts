/**
 * 登录态旁路提取器
 *
 * 从 MITM 抓包中提取 /reg 请求的 token 与 did，直接写入网关的 .env。
 * 这样无需复刻 x5-sign 签名——用户正常登录，我们从流量里取结果。
 *
 * 用法：
 *   tsx tools/extract-token.ts <抓包目录>
 */
import { readFileSync, readdirSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { parseFrames } from '../apps/server/src/lwp/frame.js';

const dir = process.argv[2];
if (!dir) {
  console.error('用法: tsx tools/extract-token.ts <抓包目录>');
  process.exit(1);
}

interface Found {
  file: string;
  mid: string;
  did: string;
  token: string;
  orgId?: string;
  at: number;
}

const found: Found[] = [];

for (const f of readdirSync(dir).filter((x) => x.endsWith('.bin')).sort()) {
  for (const fr of parseFrames(readFileSync(join(dir, f))).frames) {
    if (fr.kind !== 'req' || fr.uri !== '/reg') continue;
    const token = fr.headers.token;
    const did = fr.headers.did;
    if (!token || !did) continue;
    found.push({
      file: f,
      mid: fr.headers.mid ?? '',
      did,
      token,
      orgId: fr.headers['app-realm-orgId'],
      at: Date.now(),
    });
  }
}

if (!found.length) {
  console.log('未找到 /reg 请求。请确认：');
  console.log('  1. 抓包时钉钉处于登录状态');
  console.log('  2. 抓包目录包含 tls-desktop.dingtalk.com 的连接');
  process.exit(1);
}

const latest = found[found.length - 1]!;
console.log(`找到 ${found.length} 个 /reg 请求，取最新的：`);
console.log(`  文件:   ${latest.file}`);
console.log(`  did:    ${latest.did}`);
console.log(`  orgId:  ${latest.orgId ?? '(无)'}`);
console.log(`  token:  ${latest.token.slice(0, 40)}...（共 ${latest.token.length} 字符）`);

// 写入 .env
const envPath = join(process.cwd(), 'apps/server/.env');
const lines = [
  'PORT=8787',
  'DT_HOST=tls-desktop.dingtalk.com',
  `DT_DEVICE_ID=${latest.did}`,
  'DT_APP_KEY=564ca050be89b14ee78d692f6ded748d',
  'DT_APPKEY=85A09F60A599F5E1867EAB915A8BB07G',
  `DT_TOKEN=${latest.token}`,
  latest.orgId ? `DT_ORG_ID=${latest.orgId}` : 'DT_ORG_ID=',
  '',
];

if (existsSync(envPath)) {
  console.log(`\n覆盖已有配置: ${envPath}`);
} else {
  console.log(`\n创建配置: ${envPath}`);
}
writeFileSync(envPath, lines.join('\n'), 'utf8');
console.log('✓ 已写入。重启网关生效。');
