/** 解析 /s/sync 推送帧，提取 cid / 发送者 / 文本 */
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { parseFrames } from '../apps/server/src/lwp/frame.js';

const dir = process.argv[2]!;

for (const f of readdirSync(dir).filter((x) => x.endsWith('.bin')).sort()) {
  const { frames } = parseFrames(readFileSync(join(dir, f)));
  for (const fr of frames) {
    if (!fr.uri?.startsWith('/s/') || fr.body.length < 100) continue;
    console.log(`\n=== ${f} ${fr.uri} ${fr.body.length}B`);
    const buf = fr.body;
    const s = buf.toString('utf8');
    // 找所有中文串及其偏移
    const re = /[\u4e00-\u9fa5][\u4e00-\u9fa5A-Za-z0-9()（）@_.\-，。？！、：；\s]{3,120}/g;
    let m;
    while ((m = re.exec(s))) {
      const pre = buf.slice(Math.max(0, m.index - 30), m.index);
      const hex = pre.toString('hex');
      console.log(`  @${String(m.index).padStart(5)} 前=${hex.slice(-24)}  ${JSON.stringify(m[0].trim().slice(0, 60))}`);
    }
  }
}
