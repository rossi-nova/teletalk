/** 导出指定 URI 的完整请求体 hex，供构造请求用 */
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { parseFrames } from '../apps/server/src/lwp/frame.js';

const [dir, ...targets] = process.argv.slice(2);
if (!dir || !targets.length) {
  console.error('用法: tsx scripts/dump-bodies.ts <目录> <uri> [uri...]');
  process.exit(1);
}

const seen = new Map<string, { file: string; mid: string; len: number; hex: string }>();
for (const f of readdirSync(dir!).filter((x) => x.endsWith('.bin')).sort()) {
  const { frames } = parseFrames(readFileSync(join(dir!, f)));
  for (const fr of frames) {
    if (fr.kind !== 'req' || !fr.uri) continue;
    if (!targets.some((t) => fr.uri!.includes(t))) continue;
    if (seen.has(fr.uri)) continue;
    seen.set(fr.uri!, {
      file: f,
      mid: fr.headers.mid ?? '',
      len: fr.body.length,
      hex: fr.body.toString('hex'),
    });
  }
}

for (const [uri, v] of seen) {
  console.log(`\n=== ${uri}`);
  console.log(`  file=${v.file} mid=${v.mid} len=${v.len}`);
  console.log(`  ${v.hex.match(/.{1,96}/g)?.join('\n  ') ?? '(空)'}`);
}
