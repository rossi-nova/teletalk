/** 从抓包中提取 /reg 的 token 与 orgId */
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { parseFrames } from '../apps/server/src/lwp/frame.js';

const dir = process.argv[2]!;
for (const f of readdirSync(dir).filter((x) => x.endsWith('.bin')).sort()) {
  for (const fr of parseFrames(readFileSync(join(dir, f))).frames) {
    if (fr.kind !== 'req' || fr.uri !== '/reg') continue;
    console.log(`文件: ${f}`);
    console.log(`  did:   ${fr.headers.did ?? '-'}`);
    console.log(`  orgId: ${fr.headers['app-realm-orgId'] ?? '-'}`);
    console.log(`  token: ${fr.headers.token ?? '-'}`);
    console.log(`  mid:   ${fr.headers.mid}`);
    process.exit(0);
  }
}
console.log('未找到 /reg 请求');
