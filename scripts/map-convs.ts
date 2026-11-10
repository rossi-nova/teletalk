/** 提取 cid → 会话名 的映射 */
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { parseFrames } from '../apps/server/src/lwp/frame.js';

const dir = process.argv[2]!;
const map = new Map<string, string>();

for (const f of readdirSync(dir).filter((x) => x.endsWith('.bin')).sort()) {
  const { frames } = parseFrames(readFileSync(join(dir, f)));
  for (const fr of frames) {
    if (fr.kind !== 'res' || !fr.body.length) continue;
    const buf = fr.body;
    const s = buf.toString('utf8');
    // 找中文名
    const nameM = s.match(/[\u4e00-\u9fa5][\u4e00-\u9fa5A-Za-z0-9()（）@_.\-\s]{2,28}/);
    if (!nameM) continue;
    const name = nameM[0].trim();
    // 在附近找形如 7xxxxxxxxxx 或 cid 的数字串
    const around = buf.slice(Math.max(0, buf.indexOf(Buffer.from(name)) - 40), buf.indexOf(Buffer.from(name)));
    const ids = around.toString('latin1').match(/\d{9,20}/g);
    if (ids?.length) {
      const id = ids[ids.length - 1]!;
      if (!map.has(id)) map.set(id, name);
    }
  }
}

console.log(`提取到 ${map.size} 组映射\n`);
for (const [id, name] of [...map].slice(0, 25)) {
  console.log(`  ${id}  →  ${name}`);
}
