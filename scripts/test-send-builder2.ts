/** 从任意 IDLSend 样本反解参数，重新构造并比对 */
import { readFileSync } from 'node:fs';
import { buildSendBody } from '../apps/server/src/lwp/send-builder.js';
import { parseFrames } from '../apps/server/src/lwp/frame.js';
import { extractText } from '../apps/server/src/lwp/message-codec.js';

const file = process.argv[2]!;
const { frames } = parseFrames(readFileSync(file));

let pass = 0, fail = 0;
for (const fr of frames) {
  if (fr.kind !== 'req' || fr.uri !== '/r/IDLSend/send') continue;
  const b = fr.body;
  // 反解参数
  const cid = b.slice(4, 11).toString('latin1');            // 7 字节，偏移 4
  const uidM = b.slice(11, 30).toString('latin1').match(/\d{8,15}/);
  const orgM = b.toString('utf8').match(/"orgId":"(\d+)"/);
  const nameM = b.toString('utf8').match(/\u0008..([\u4e00-\u9fa5A-Za-z0-9()（）]{2,30})/u);
  const text = extractText(b);
  if (!uidM || !orgM || !nameM || !text) { console.log(`  跳过（字段不全）${file}`); continue; }

  const rebuilt = buildSendBody({
    cid, uid: uidM[0], orgId: orgM[1]!, convName: nameM[1]!, text,
  });
  const ok = rebuilt.equals(b);
  console.log(`${ok ? '✓' : '✗'} ${file}  cid=${cid} text=${JSON.stringify(text.slice(0, 12))}`);
  if (!ok) {
    for (let i = 0; i < Math.max(rebuilt.length, b.length); i++) {
      if (rebuilt[i] !== b[i]) { console.log(`   首个差异 @${i}`); break; }
    }
    fail++;
  } else pass++;
}
console.log(`\n${pass} 通过, ${fail} 失败`);
