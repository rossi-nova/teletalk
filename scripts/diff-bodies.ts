/** 对比同一条连接里的多次发送，找恒定段与变动段 */
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { parseFrames } from '../apps/server/src/lwp/frame.js';

const dir = process.argv[2]!;
const bodies: { file: string; body: Buffer }[] = [];

for (const f of readdirSync(dir).filter((x) => x.endsWith('.bin')).sort()) {
  for (const fr of parseFrames(readFileSync(join(dir, f))).frames) {
    if (fr.kind === 'req' && fr.uri === '/r/IDLSend/send') bodies.push({ file: f, body: fr.body });
  }
}

// 只取 uid 为 79553200501 的前几条（同一个人）
const same = bodies.filter((b) => b.body.slice(11, 30).toString('latin1').includes('79553200501')).slice(0, 4);
if (same.length < 2) { console.log('样本不足'); process.exit(0); }

console.log(`对比 ${same.length} 条：`);
same.forEach((b) => console.log(`  ${b.file}  ${b.body.length}B`));

// 逐字节对比：找出所有样本都相同的区间
const minLen = Math.min(...same.map((b) => b.body.length));
const sameBytes: boolean[] = [];
for (let i = 0; i < minLen; i++) {
  sameBytes.push(same.every((b) => b.body[i] === same[0]!.body[i]));
}

// 输出相同/不同的区间
let start = 0, cur = sameBytes[0];
const runs: string[] = [];
for (let i = 1; i <= minLen; i++) {
  const v = i < minLen ? sameBytes[i] : !cur;
  if (v !== cur) {
    const seg = same[0]!.body.slice(start, i);
    const label = cur ? '同' : '异';
    const preview = cur ? seg.toString('hex').slice(0, 40) : `[${i - start}B]`;
    runs.push(`  ${String(start).padStart(4)}-${String(i).padStart(4)} ${label} ${preview}`);
    start = i;
    cur = v;
  }
}
console.log('\n区间（前 30 段）：');
console.log(runs.slice(0, 30).join('\n'));
