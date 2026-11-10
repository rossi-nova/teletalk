// 扫描 PE 文件内嵌的 protobuf FileDescriptorProto，输出 desc-list.json / desc-all.bin
// 用法: node scan-descriptors.cjs [path/to/MainFrame.dll]
const fs = require('fs');
const path = require('path');
const target = process.argv[2] || 'C:/Program Files (x86)/DingDing/main/current/MainFrame.dll';
const buf = fs.readFileSync(target);

function rv(b, p) { let v = 0, s = 0, c; do { c = b[p++]; v += (c & 0x7f) * 2 ** s; s += 7; } while (c & 0x80 && s < 64); return [v, p]; }

function scanFdp(b, start) {
  let p = start, ok = false, first = true;
  for (let guard = 0; guard < 5000; guard++) {
    if (p >= b.length) return ok ? p : null;
    const tag = b[p], fn = tag >>> 3, wt = tag & 7;
    if (fn < 1 || fn > 12 || wt > 5 || wt === 3 || wt === 4) return ok ? p : null;
    if (first) { if (fn !== 1 || wt !== 2) return null; first = false; }
    p++;
    if (wt === 0) { [, p] = rv(b, p); }
    else if (wt === 2) { let l; [l, p] = rv(b, p); if (l > 5_000_000) return ok ? p : null; p += l; }
    else if (wt === 5) p += 4;
    else if (wt === 1) p += 8;
    if (p > b.length) return ok ? p : null;
    if (p < b.length) {
      const t = b[p], f2 = t >>> 3, w2 = t & 7;
      if (f2 < 1 || f2 > 12 || w2 > 5 || w2 === 3 || w2 === 4) return p;
    }
    ok = true;
  }
  return ok ? p : null;
}

const out = [];
for (let i = 0; i < buf.length - 3; i++) {
  if (buf[i] !== 0x0a) continue;
  const len = buf[i + 1];
  if (len < 3 || len > 80) continue;
  const nm = buf.slice(i + 2, i + 2 + len).toString('latin1');
  if (!/^[\w./-]+\.proto$/.test(nm)) continue;
  const end = scanFdp(buf, i);
  if (!end || end - i < 20) continue;
  out.push({ off: i, len: end - i, name: nm, raw: buf.slice(i, end) });
  i = end - 1;
}
console.log('descriptor 数量:', out.length);
console.log([...new Set(out.map(o => o.name))].join('\n'));
const dir = __dirname;
fs.writeFileSync(path.join(dir, 'desc-list.json'), JSON.stringify(out.map(o => ({ off: o.off, len: o.len, name: o.name })), null, 1));
fs.writeFileSync(path.join(dir, 'desc-all.bin'), Buffer.concat(out.map(o => o.raw)));
