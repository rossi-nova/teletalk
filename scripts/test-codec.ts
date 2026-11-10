/** 用抓包样本验证 LWP 帧解析与消息编解码 */
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { parseFrames } from '../apps/server/src/lwp/frame.js';
import { extractText } from '../apps/server/src/lwp/message-codec.js';

const dir = process.argv[2];
if (!dir) { console.error('用法: tsx scripts/test-codec.ts <抓包目录>'); process.exit(1); }

let total = 0, reqs = 0, sends = 0, texts = 0;
const uris = new Map<string, number>();

for (const f of readdirSync(dir).filter((x) => x.endsWith('.bin'))) {
  const { frames } = parseFrames(readFileSync(join(dir, f)));
  for (const fr of frames) {
    total++;
    if (fr.kind === 'req' && fr.uri) {
      reqs++;
      uris.set(fr.uri, (uris.get(fr.uri) ?? 0) + 1);
      if (fr.uri === '/r/IDLSend/send') {
        sends++;
        const t = extractText(fr.body);
        if (t) { texts++; console.log(`  正文: ${JSON.stringify(t.slice(0, 40))}`); }
      }
    }
  }
}

console.log(`\n帧总数 ${total}，请求 ${reqs}，IDLSend ${sends}，解出正文 ${texts}`);
console.log('\nTop 5 URI:');
[...uris.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).forEach(([u, n]) => console.log(`  ${n}x ${u}`));
