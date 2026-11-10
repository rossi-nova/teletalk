/** 在所有帧里找 uid → 昵称 的关联 */
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { parseFrames } from '../apps/server/src/lwp/frame.js';

const dir = process.argv[2]!;
const pairs = new Map<string, string>();

for (const f of readdirSync(dir).filter((x) => x.endsWith('.bin')).sort()) {
  for (const fr of parseFrames(readFileSync(join(dir, f))).frames) {
    if (!fr.body.length) continue;
    const s = fr.body.toString('utf8');
    // 模式1: "senderId":123,... 附近的中文
    // 模式2: uid\u0000nick 之类
    // 简化：找 「数字紧邻 中文名」的片段
    const re = /(\d{6,12})[\u0000-\u001f\u0080-\u00ff]{0,3}([\u4e00-\u9fa5][\u4e00-\u9fa5A-Za-z0-9()（）]{1,15})/g;
    let m;
    while ((m = re.exec(s))) {
      const uid = m[1]!, nick = m[2]!;
      if (!pairs.has(uid)) pairs.set(uid, nick);
    }
  }
}
console.log(`找到 ${pairs.size} 组 uid→昵称`);
for (const [u, n] of [...pairs].slice(0, 20)) console.log(`  ${u} → ${n}`);
