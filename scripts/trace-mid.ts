/** 按 mid 追踪：找到请求对应哪个响应文件 */
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { parseFrames } from '../apps/server/src/lwp/frame.js';

const [dir, targetUri] = process.argv.slice(2);
const files = readdirSync(dir!).filter((x) => x.endsWith('.bin')).sort();

// 1) 找请求 mid
const mids = new Map<string, string>();
for (const f of files) {
  const { frames } = parseFrames(readFileSync(join(dir!, f)));
  for (const fr of frames) {
    if (fr.kind === 'req' && fr.uri?.includes(targetUri!)) {
      mids.set(fr.headers.mid ?? '', targetUri!);
      console.log(`请求 ${targetUri} mid=${fr.headers.mid} @ ${f} body=${fr.body.length}B`);
    }
  }
}

// 2) 找响应
for (const f of files) {
  const { frames } = parseFrames(readFileSync(join(dir!, f)));
  for (const fr of frames) {
    if (fr.kind === 'res' && mids.has(fr.headers.mid ?? '')) {
      console.log(`\n响应 mid=${fr.headers.mid} @ ${f} body=${fr.body.length}B`);
      const s = fr.body.toString('utf8');
      const re = /[\u4e00-\u9fa5A-Za-z0-9()（）@_.\-]{4,40}/g;
      let m, n = 0;
      while ((m = re.exec(s)) && n < 12) { console.log(`  @${m.index}: ${JSON.stringify(m[0])}`); n++; }
    }
  }
}
