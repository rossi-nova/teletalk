/** 列出所有非请求的推送帧（无 uri 的响应） */
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { parseFrames } from '../apps/server/src/lwp/frame.js';

const dir = process.argv[2]!;
const stats = new Map<string, number>();
for (const f of readdirSync(dir).filter((x) => x.endsWith('.bin')).sort().slice(0, 40)) {
  for (const fr of parseFrames(readFileSync(join(dir, f))).frames) {
    if (fr.kind !== 'res') continue;
    const key = fr.uri ?? '(push)';
    stats.set(key, (stats.get(key) ?? 0) + 1);
  }
}
console.log('响应帧来源：');
for (const [k, v] of [...stats].sort((a, b) => b[1] - a[1])) console.log(`  ${String(v).padStart(5)}  ${k}`);
