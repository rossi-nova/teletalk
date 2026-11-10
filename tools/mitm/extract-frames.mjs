/** 从抓包文件提取指定 URI 的 LWP 帧，输出 head + body hex */
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const dir = process.argv[2];
const target = process.argv[3] || 'IDLSend/send';

const parseAll = (buf) => {
  const frames = [];
  let off = 0;
  for (let guard = 0; guard < 50000 && off < buf.length - 1; guard++) {
    // 期望 "LWP " 或 "200\n"
    const isLwp = buf.slice(off, off + 4).toString('latin1') === 'LWP ';
    const isRes = buf[off] === 0x32 && buf[off + 1] === 0x30 && buf[off + 2] === 0x30 && buf[off + 3] === 0x0a;
    if (!isLwp && !isRes) {
      const a = buf.indexOf('LWP ', off + 1);
      const b2 = buf.indexOf(Buffer.from('200\n'), off + 1);
      const next = [a, b2].filter((x) => x > off).sort((x, y) => x - y)[0];
      if (next === undefined) break;
      off = next;
      continue;
    }
    const he = buf.indexOf('\n\n', off);
    if (he < 0) break;
    const head = buf.slice(off, he).toString('latin1');
    const hdr = {};
    for (const l of head.split('\n').slice(1)) { const i = l.indexOf(':'); if (i > 0) hdr[l.slice(0, i)] = l.slice(i + 1); }
    const len = Number(hdr.len || 0);
    const bodyStart = he + 2;
    frames.push({
      uri: isLwp ? head.split('\n')[0].slice(4) : null,
      code: isLwp ? null : Number(head.split('\n')[0]),
      hdr, body: buf.slice(bodyStart, bodyStart + len),
    });
    off = bodyStart + len;
  }
  return frames;
};

const files = readdirSync(dir).filter((f) => f.endsWith('.bin')).sort();
const out = [];
for (const f of files) {
  for (const fr of parseAll(readFileSync(join(dir, f)))) {
    if (fr.uri && fr.uri.includes(target)) out.push({ file: f, ...fr });
  }
}
console.log(JSON.stringify(out.map((o) => ({
  file: o.file, uri: o.uri, mid: o.hdr.mid, len: o.body.length, hex: o.body.toString('hex'),
})), null, 1));
