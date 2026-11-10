import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { parseFrames } from '../apps/server/src/lwp/frame.js';
import { extractText } from '../apps/server/src/lwp/message-codec.js';

const dir = process.argv[2]!;
const rows: { file: string; body: Buffer; text: string }[] = [];
for (const f of readdirSync(dir).filter((x) => x.endsWith('.bin')).sort()) {
  for (const fr of parseFrames(readFileSync(join(dir, f))).frames) {
    if (fr.kind !== 'req' || fr.uri !== '/r/IDLSend/send') continue;
    const t = extractText(fr.body);
    if (t) rows.push({ file: f, body: fr.body, text: t });
  }
}

// 取最长的样本作为基准，找共同前缀
const base = rows.reduce((a, b) => (a.body.length > b.body.length ? a : b));
console.log(`基准: ${base.file} (${base.body.length}B)\n`);

// 找出所有样本都相同的字节位（只在基准长度内比）
const same: boolean[] = [];
for (let i = 0; i < base.body.length; i++) {
  same.push(rows.every((r) => i < r.body.length && r.body[i] === base.body[i]));
}

// 输出「异」的区间
let start = 0, cur = same[0];
const diffs: [number, number][] = [];
for (let i = 1; i <= base.body.length; i++) {
  const v = i < base.body.length ? same[i] : !cur;
  if (v !== cur) {
    if (!cur) diffs.push([start, i]);
    start = i; cur = v;
  }
}
console.log('不同区间：');
for (const [s, e] of diffs) {
  console.log(`  ${String(s).padStart(4)}-${String(e).padStart(4)} (${e - s}B)  基准值=${base.body.slice(s, Math.min(e, s + 20)).toString('hex')}`);
}
