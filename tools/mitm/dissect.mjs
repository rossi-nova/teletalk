import { readFileSync } from 'node:fs';

const file = process.argv[2];
const b = readFileSync(file);
const i = b.indexOf('LWP ');
const he = b.indexOf('\n\n', i);
const head = b.slice(i, he).toString('latin1');
const hdr = {};
for (const l of head.split('\n').slice(1)) { const k = l.indexOf(':'); if (k > 0) hdr[l.slice(0, k)] = l.slice(k + 1); }
const body = b.slice(he + 2, he + 2 + Number(hdr.len || 0));

let p = 0;
const rv = () => { let v = 0, s = 0, c; do { c = body[p++]; v += (c & 0x7f) * 2 ** s; s += 7; } while (c & 0x80 && s < 64); return v; };

console.log(`${head.split('\n')[0]}  (body ${body.length}B)\n`);
for (let g = 0; g < 200 && p < body.length; g++) {
  const start = p;
  const tag = rv();
  const fn = tag >>> 3, wt = tag & 7;
  if (fn === 0) break;
  if (wt === 0) {
    console.log(`field ${fn}  varint  = ${rv()}`);
  } else if (wt === 2) {
    const len = rv();
    const chunk = body.slice(p, p + len);
    p += len;
    const utf8 = chunk.toString('utf8');
    const isText = /^[\x20-\x7e\u4e00-\u9fa5\u3000-\u303f\uff00-\uffef]*$/u.test(utf8) && chunk.every(x => x !== 0);
    if (isText && len > 0) {
      console.log(`field ${fn}  string(${len}) = ${JSON.stringify(utf8)}`);
    } else {
      // 尝试当子消息解
      const sub = tryProto(chunk);
      if (sub) {
        console.log(`field ${fn}  message(${len}) {`);
        for (const s of sub) console.log(`    ${s}`);
        console.log(`  }`);
      } else {
        console.log(`field ${fn}  bytes(${len}) = ${chunk.toString('hex').slice(0, 48)}`);
      }
    }
  } else if (wt === 5) { console.log(`field ${fn}  fixed32 = ${body.readUInt32LE(p)}`); p += 4; }
  else if (wt === 1) { console.log(`field ${fn}  fixed64 = ${body.readBigUInt64LE(p)}`); p += 8; }
  else { console.log(`field ${fn}  wire=${wt} 未处理 @${start}`); break; }
}

function tryProto(buf) {
  if (buf.length < 2) return null;
  let q = 0;
  const rvq = () => { let v = 0, s = 0, c; do { c = buf[q++]; v += (c & 0x7f) * 2 ** s; s += 7; } while (c & 0x80 && s < 64); return v; };
  const out = [];
  try {
    while (q < buf.length) {
      const t = rvq(); const f = t >>> 3, w = t & 7;
      if (f === 0 || f > 200) return null;
      if (w === 0) out.push(`field ${f} varint = ${rvq()}`);
      else if (w === 2) { const l = rvq(); const c = buf.slice(q, q + l); q += l; if (q > buf.length) return null;
        const u = c.toString('utf8');
        out.push(/^[\x20-\x7e\u4e00-\u9fa5]*$/u.test(u) && c.every(x => x !== 0) ? `field ${f} string = ${JSON.stringify(u)}` : `field ${f} bytes = ${c.toString('hex').slice(0, 32)}`); }
      else if (w === 5) { out.push(`field ${f} fixed32 = ${buf.readUInt32LE(q)}`); q += 4; }
      else if (w === 1) { out.push(`field ${f} fixed64 = ${buf.readBigUInt64LE(q)}`); q += 8; }
      else return null;
    }
  } catch { return null; }
  return out.length ? out : null;
}
