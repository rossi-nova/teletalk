import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { parseFrames } from '../apps/server/src/lwp/frame.js';
import { parseSync } from '../apps/server/src/lwp/sync-parser.js';

const dir = process.argv[2]!;
let total = 0;
const seen = new Set<string>();
for (const f of readdirSync(dir).filter((x) => x.endsWith('.bin')).sort()) {
  const { frames } = parseFrames(readFileSync(join(dir, f)));
  for (const fr of frames) {
    if (!fr.uri?.startsWith('/s/')) continue;
    for (const m of parseSync(fr.body)) {
      if (seen.has(m.messageId)) continue;
      seen.add(m.messageId);
      total++;
      console.log(`[${m.senderNick ?? m.senderId}] ${m.text.slice(0, 50)}`);
      console.log(`    conv=${m.conversationId} open=${m.openConversationId ?? '-'}`);
    }
  }
}
console.log(`\n共 ${total} 条不重复消息`);
