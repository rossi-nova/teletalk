import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const dir = process.argv[2];
const rows = [];
for (const f of readdirSync(dir).filter((x) => x.endsWith('.bin')).sort()) {
  const buf = readFileSync(join(dir, f));
  let off = 0;
  for (let g = 0; g < 5000 && off < buf.length - 1; g++) {
    const isLwp = buf.slice(off, off + 4).toString('latin1') === 'LWP ';
    const isRes = buf.slice(off, off + 4).toString('latin1') === '200\n';
    if (!isLwp && !isRes) {
      const a = buf.indexOf('LWP ', off + 1);
      const r = buf.indexOf(Buffer.from('200\n'), off + 1);
      const nx = [a, r].filter((x) => x > off).sort((x, y) => x - y)[0];
      if (nx === undefined) break;
      off = nx; continue;
    }
    const he = buf.indexOf('\n\n', off);
    if (he < 0) break;
    const head = buf.slice(off, he).toString('latin1');
    const hdr = {};
    for (const l of head.split('\n').slice(1)) { const i = l.indexOf(':'); if (i > 0) hdr[l.slice(0, i)] = l.slice(i + 1); }
    const len = Number(hdr.len || 0);
    const body = buf.slice(he + 2, he + 2 + len);
    if (isLwp && head.startsWith('LWP /r/IDLSend/send')) {
      const j = body.indexOf(Buffer.from([0x81, 0x01]));
      // 尾部固定串
      const tail = Buffer.from([0x07, 0x90, 0x06, 0x01, 0x07]);
      const t = body.indexOf(tail, j);
      if (j >= 0 && t > 0) {
        const after = body.slice(j + 2, t);
        rows.push({ file: f, mid: hdr.mid, bodyLen: len, region: after.length, head: after.slice(0, 6).toString('hex'), txtLen: t - (j + 2) });
      }
    }
    off = he + 2 + len;
  }
}
rows.sort((a, b) => a.region - b.region);
console.log('region(含marker) | marker头 | 总body');
for (const r of rows) console.log(`${String(r.region).padStart(5)}  ${r.head.padEnd(18)} ${r.bodyLen}`);
