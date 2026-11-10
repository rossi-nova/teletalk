import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { parseFrames } from '../apps/server/src/lwp/frame.js';
import { parseProfiles, mergeProfiles } from '../apps/server/src/lwp/profile-parser.js';

const dir = process.argv[2]!;
const all = [];
for (const f of readdirSync(dir).filter((x) => x.endsWith('.bin')).sort()) {
  for (const fr of parseFrames(readFileSync(join(dir, f))).frames) {
    if (fr.kind !== 'res' || fr.body.length < 100) continue;
    // 只处理含拼音模式的
    if (!/[a-z]+\^[a-z]+/.test(fr.body.toString('utf8'))) continue;
    all.push(...parseProfiles(fr.body));
  }
}
const map = mergeProfiles(all);
console.log(`提取 ${map.size} 个用户\n`);
for (const [uid, nick] of [...map].slice(0, 25)) console.log(`  ${uid} → ${nick}`);
