/** 从抓包响应中提取会话名与 cid 的对应关系 */
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { parseFrames } from '../apps/server/src/lwp/frame.js';

const dir = process.argv[2]!;
const hits: Array<{ file: string; uri: string | null; snippets: string[] }> = [];

for (const f of readdirSync(dir).filter((x) => x.endsWith('.bin')).sort()) {
  const { frames } = parseFrames(readFileSync(join(dir, f)));
  for (const fr of frames) {
    if (fr.kind !== 'res' || !fr.body.length) continue;
    const text = fr.body.toString('utf8');
    const names = text.match(/[\u4e00-\u9fa5A-Za-z0-9()（）@_.\-\s]{4,40}/g) ?? [];
    const good = names.filter((n) => /[\u4e00-\u9fa5]/.test(n) && n.trim().length >= 4);
    if (good.length) hits.push({ file: f, uri: fr.uri ?? null, snippets: [...new Set(good)].slice(0, 5) });
  }
}

// 只显示可能是会话名的
const seen = new Set<string>();
for (const h of hits) {
  for (const s of h.snippets) {
    const t = s.trim();
    if (seen.has(t) || t.length > 30) continue;
    seen.add(t);
    console.log(`  ${t}`);
  }
}
console.log(`\n共 ${seen.size} 个候选名称，来自 ${hits.length} 个响应`);
