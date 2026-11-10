import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { parseFrames } from '../apps/server/src/lwp/frame.js';
import { extractText } from '../apps/server/src/lwp/message-codec.js';

const dir = process.argv[2]!;
const rows: string[] = [];
for (const f of readdirSync(dir).filter((x) => x.endsWith('.bin')).sort()) {
  for (const fr of parseFrames(readFileSync(join(dir, f))).frames) {
    if (fr.kind !== 'req' || fr.uri !== '/r/IDLSend/send') continue;
    const b = fr.body;
    const cid = b.slice(4, 11).toString('latin1');
    const uid = b.slice(11, 30).toString('latin1').match(/\d{8,15}/)?.[0] ?? '-';
    const org = b.toString('utf8').match(/"orgId":"(\d+)"/)?.[1] ?? '-';
    const txt = extractText(b) ?? '-';
    rows.push(`${f}  cid=${cid}  uid=${uid}  org=${org}  text=${JSON.stringify(txt.slice(0, 15))}`);
  }
}
console.log(rows.join('\n'));
