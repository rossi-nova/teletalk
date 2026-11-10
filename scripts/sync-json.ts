import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { parseFrames } from '../apps/server/src/lwp/frame.js';

const dir = process.argv[2]!;
for (const f of readdirSync(dir).filter((x) => x.endsWith('.bin')).sort()) {
  const { frames } = parseFrames(readFileSync(join(dir, f)));
  for (const fr of frames) {
    if (fr.uri !== '/s/sync' && fr.uri !== '/s/synca') continue;
    const s = fr.body.toString('utf8');
    const i = s.indexOf('{');
    if (i < 0) continue;
    // 尝试从每个 { 开始解析 JSON
    let ok = false;
    for (let p = i; p < s.length && p < i + 600; p++) {
      if (s[p] !== '{') continue;
      const sub = s.slice(p);
      const end = sub.indexOf('\u0000');
      const cand = end > 0 ? sub.slice(0, end) : sub;
      try {
        const j = JSON.parse(cand);
        console.log(`\n[${f}] ${fr.uri} —— JSON 解析成功`);
        console.log(JSON.stringify(j, null, 1).slice(0, 1200));
        ok = true;
        break;
      } catch { /* 继续找下一个起始位置 */ }
    }
    if (!ok) console.log(`[${f}] ${fr.uri} —— 非纯 JSON，${fr.body.length}B`);
  }
}
