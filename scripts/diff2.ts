/** 精确定位：用「正文相同、长度相同」的样本对比，排除长度对齐干扰 */
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { parseFrames } from '../apps/server/src/lwp/frame.js';
import { extractText } from '../apps/server/src/lwp/message-codec.js';

const dir = process.argv[2]!;
const all: { file: string; body: Buffer; text: string }[] = [];
for (const f of readdirSync(dir).filter((x) => x.endsWith('.bin')).sort()) {
  for (const fr of parseFrames(readFileSync(join(dir, f))).frames) {
    if (fr.kind !== 'req' || fr.uri !== '/r/IDLSend/send') continue;
    const t = extractText(fr.body);
    if (t) all.push({ file: f, body: fr.body, text: t });
  }
}

// 找同 uid 的
const same = all.filter((b) => b.body.slice(11, 30).toString('latin1').includes('79553200501'));
console.log(`同 uid 样本 ${same.length} 条\n`);

// 按长度分组，同长度内对比（排除长度干扰）
const byLen = new Map<number, typeof same>();
for (const s of same) {
  if (!byLen.has(s.body.length)) byLen.set(s.body.length, []);
  byLen.get(s.body.length)!.push(s);
}

for (const [len, group] of byLen) {
  if (group.length < 2) continue;
  console.log(`长度 ${len}B，${group.length} 条：`);
  const a = group[0]!.body, b = group[1]!.body;
  const diffs: number[] = [];
  for (let i = 0; i < len; i++) if (a[i] !== b[i]) diffs.push(i);
  console.log(`  差异字节偏移: ${diffs.slice(0, 40).join(', ')}${diffs.length > 40 ? ' ...' : ''}`);
  console.log(`  共 ${diffs.length} 处不同`);
  // 打印差异段的上下文
  if (diffs.length && diffs.length < 30) {
    for (const d of diffs.slice(0, 8)) {
      console.log(`    @${d}: A=${a[d]!.toString(16)} B=${b[d]!.toString(16)}  上下文 ${a.slice(Math.max(0,d-4), d+5).toString('hex')}`);
    }
  }
  console.log();
}
