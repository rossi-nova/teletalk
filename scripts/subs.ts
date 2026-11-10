import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { parseFrames } from '../apps/server/src/lwp/frame.js';

const dir = process.argv[2]!;
const subs = new Set<string>();
for (const f of readdirSync(dir).filter((x) => x.endsWith('.bin')).sort()) {
  for (const fr of parseFrames(readFileSync(join(dir, f))).frames) {
    if (fr.kind === 'req' && fr.uri?.startsWith('/s/')) subs.add(fr.uri);
  }
}
console.log('订阅主题：');
console.log([...subs].sort().join('\n'));
