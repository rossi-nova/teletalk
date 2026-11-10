import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { parseFrames } from '../apps/server/src/lwp/frame.js';

const dir = process.argv[2]!;
const keywords = ['qr', 'QR', 'scan', 'Scan', 'confirm', 'Confirm', 'login', 'Login', 'auth', 'token'];
const hits = new Map<string, string[]>();

for (const f of readdirSync(dir).filter((x) => x.endsWith('.bin')).sort()) {
  for (const fr of parseFrames(readFileSync(join(dir, f))).frames) {
    if (fr.kind !== 'res' || fr.body.length < 10) continue;
    const s = fr.body.toString('latin1');
    for (const k of keywords) {
      if (s.includes(k)) {
        if (!hits.has(k)) hits.set(k, []);
        if (hits.get(k)!.length < 3) hits.get(k)!.push(`${f}:${fr.body.length}B`);
      }
    }
  }
}
for (const [k, v] of hits) console.log(`${k}: ${v.join(', ')}`);
