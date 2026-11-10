import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { parseFrames } from '../apps/server/src/lwp/frame.js';

const dir = process.argv[2]!;
for (const f of readdirSync(dir).filter((x) => x.endsWith('.bin')).sort().slice(0, 60)) {
  const { frames } = parseFrames(readFileSync(join(dir, f)));
  for (const fr of frames) {
    if (fr.body.length < 50) continue;
    const s = fr.body.toString('utf8');
    const cn = s.match(/[\u4e00-\u9fa5]{2,}/g);
    if (cn && cn.length >= 2) {
      console.log(`\n[${f}] uri=${fr.uri ?? '(res)'} ${fr.body.length}B`);
      console.log('  中文:', [...new Set(cn)].slice(0, 8).join(' / '));
    }
  }
}
