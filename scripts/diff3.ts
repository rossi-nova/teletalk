import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { parseFrames } from '../apps/server/src/lwp/frame.js';
import { extractText } from '../apps/server/src/lwp/message-codec.js';

const dir = process.argv[2]!;
const rows: { file: string; body: Buffer; text: string; conv: string }[] = [];
for (const f of readdirSync(dir).filter((x) => x.endsWith('.bin')).sort()) {
  for (const fr of parseFrames(readFileSync(join(dir, f))).frames) {
    if (fr.kind !== 'req' || fr.uri !== '/r/IDLSend/send') continue;
    const b = fr.body;
    const i8 = b.lastIndexOf(Buffer.from([0x08, 0xb7]));
    const i12 = b.indexOf(Buffer.from([0x12, 0x83, 0x01]), i8);
    const conv = i8 >= 0 && i12 > i8 ? b.slice(i8 + 2, i12).toString('utf8') : '';
    rows.push({ file: f, body: b, text: extractText(b) ?? '', conv });
  }
}
const byConv = new Map<string, typeof rows>();
for (const r of rows) {
  if (!r.conv) continue;
  if (!byConv.has(r.conv)) byConv.set(r.conv, []);
  byConv.get(r.conv)!.push(r);
}
for (const [conv, group] of byConv) {
  if (group.length < 2) continue;
  console.log(`\n会话「${conv}」${group.length} 条`);
  // 两两对比，找共同差异位置
  const a = group[0]!.body;
  const common = new Map<number, Set<string>>();
  for (const g of group) {
    if (g.body.length !== a.length) { console.log('  长度不一致，跳过'); break; }
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== g.body[i]) {
        if (!common.has(i)) common.set(i, new Set());
        common.get(i)!.add(`${g.body[i]}`);
      }
    }
  }
  if (common.size) {
    console.log(`  恒定变动位置: ${[...common.keys()].slice(0, 30).join(', ')}`);
    for (const [i, vals] of [...common].slice(0, 6)) {
      console.log(`    @${i}: ${a[i]!.toString(16)} vs {${[...vals].join(',')}}  ctx=${a.slice(Math.max(0,i-3),i+4).toString('hex')}`);
    }
  } else console.log('  完全相同（长度和内容）');
}
