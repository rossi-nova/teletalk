import { readFileSync } from 'node:fs';
import { parseFrames } from '../apps/server/src/lwp/frame.js';

const [file, keyword] = process.argv.slice(2);
const { frames } = parseFrames(readFileSync(file!));
for (const fr of frames) {
  if (fr.kind !== 'res' || !fr.body.length) continue;
  const s = fr.body.toString('latin1');
  if (!s.includes(keyword!)) continue;
  console.log(`\n--- ${fr.body.length}B`);
  const txt = fr.body.toString('utf8').replace(/[^\x20-\x7e\u4e00-\u9fa5]/g, '.');
  console.log(txt.slice(0, 400));
}
