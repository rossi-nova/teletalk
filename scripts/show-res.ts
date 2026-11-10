import { readFileSync } from 'node:fs';
import { parseFrames } from '../apps/server/src/lwp/frame.js';

const file = process.argv[2]!;
const { frames } = parseFrames(readFileSync(file));
let i = 0;
for (const fr of frames) {
  if (fr.kind !== 'res' || !fr.body.length) continue;
  const s = fr.body.toString('utf8');
  if (!/[\u4e00-\u9fa5]/.test(s)) continue;
  console.log(`\n--- 帧 #${i} (${fr.body.length}B) mid=${fr.headers.mid}`);
  // 打印可读片段及其偏移
  const re = /[\u4e00-\u9fa5A-Za-z0-9()（）@_.\-\[\]{}":,\s]{6,80}/g;
  let m, n = 0;
  while ((m = re.exec(s)) && n < 8) {
    const t = m[0].trim();
    if (t.length < 6) continue;
    console.log(`  @${m.index}: ${JSON.stringify(t.slice(0, 70))}`);
    n++;
  }
  i++;
  if (i > 3) break;
}
