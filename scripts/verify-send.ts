/** 全样本验证发送构造器 */
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { buildSendBody } from '../apps/server/src/lwp/send-builder.js';
import { parseFrames } from '../apps/server/src/lwp/frame.js';
import { extractText } from '../apps/server/src/lwp/message-codec.js';

const dir = process.argv[2]!;
let pass = 0, fail = 0;

for (const f of readdirSync(dir).filter((x) => x.endsWith('.bin')).sort()) {
  const { frames } = parseFrames(readFileSync(join(dir, f)));
  for (const fr of frames) {
    if (fr.kind !== 'req' || fr.uri !== '/r/IDLSend/send') continue;
    const body = fr.body;
    const cid = body.slice(4, 11).toString('latin1');
    const uid = body.slice(11, 30).toString('latin1').match(/\d{8,15}/)?.[0];
    const orgId = body.toString('utf8').match(/"orgId":"(\d+)"/)?.[1];
    const text = extractText(body);
    if (!uid || !orgId || !text) continue;
    // 名字：最后一个 08 b7 之后到 12
    const i8 = body.lastIndexOf(Buffer.from([0x08, 0xb7]));
    const i12 = body.indexOf(Buffer.from([0x12, 0x83, 0x01]), i8);
    if (i8 < 0 || i12 < 0) continue;
    const name = body.slice(i8 + 2, i12).toString('utf8');

    const rebuilt = buildSendBody({ cid, uid, orgId, convName: name, text });
    const ok = rebuilt.equals(body);
    if (ok) { pass++; }
    else {
      fail++;
      let first = 0;
      for (let i = 0; i < Math.max(body.length, rebuilt.length); i++) if (body[i] !== rebuilt[i]) { first = i; break; }
      console.log(`✗ ${f} len=${body.length}/${rebuilt.length} 差异@${first} text=${JSON.stringify(text.slice(0, 10))}`);
    }
  }
}
console.log(`\n${pass} 通过, ${fail} 失败`);
process.exit(fail ? 1 : 0);
