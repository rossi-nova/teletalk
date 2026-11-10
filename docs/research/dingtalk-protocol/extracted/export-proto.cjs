// 把 desc-list.json 还原成 .proto 文本
// 用法: node export-proto.cjs [path/to/MainFrame.dll]
const fs = require('fs');
const path = require('path');
const dir = __dirname;
const target = process.argv[2] || 'C:/Program Files (x86)/DingDing/main/current/MainFrame.dll';
const buf = fs.readFileSync(target);
const list = JSON.parse(fs.readFileSync(path.join(dir, 'desc-list.json'), 'utf8'));

function rv(b, p) { let v = 0, s = 0, c; do { c = b[p++]; v += (c & 0x7f) * 2 ** s; s += 7; } while (c & 0x80 && s < 64); return [v, p]; }
function pf(b, start, end) {
  const f = []; let p = start;
  while (p < end) {
    const tag = b[p], fn = tag >>> 3, wt = tag & 7; p++;
    if (wt === 0) { let v; [v, p] = rv(b, p); f.push({ fn, wt, v }); }
    else if (wt === 2) { let l; [l, p] = rv(b, p); f.push({ fn, wt, v: b.slice(p, p + l) }); p += l; }
    else if (wt === 5) { f.push({ fn, wt, v: b.readUInt32LE(p) }); p += 4; }
    else if (wt === 1) { f.push({ fn, wt, v: b.readBigUInt64LE(p) }); p += 8; }
    else break;
  }
  return f;
}
const T = { 1: 'double', 2: 'float', 3: 'int64', 4: 'uint64', 5: 'int32', 6: 'fixed64', 7: 'fixed32', 8: 'bool', 9: 'string', 11: 'message', 12: 'bytes', 13: 'uint32', 14: 'enum', 15: 'sfixed32', 16: 'sfixed64', 17: 'sint32', 18: 'sint64' };
const out = [];
function dumpMsg(b, ind) {
  const f = pf(b, 0, b.length);
  const name = f.find(x => x.fn === 1)?.v?.toString() ?? '?';
  out.push(`${ind}message ${name} {`);
  for (const fl of f.filter(x => x.fn === 2)) {
    const ff = pf(fl.v, 0, fl.v.length);
    const fn = ff.find(x => x.fn === 1)?.v?.toString();
    const no = ff.find(x => x.fn === 3)?.v;
    const ty = ff.find(x => x.fn === 5)?.v;
    const lab = ff.find(x => x.fn === 4)?.v;
    const tn = ff.find(x => x.fn === 6)?.v?.toString();
    const pre = lab === 3 ? 'repeated ' : lab === 2 ? 'required ' : '';
    out.push(`${ind}  ${pre}${T[ty] || ty} ${tn ? tn + ' ' : ''}${fn} = ${no};`);
  }
  for (const n of f.filter(x => x.fn === 3).map(x => x.v)) dumpMsg(n, ind + '  ');
  out.push(`${ind}}`);
}
for (const d of list) {
  if (d.name.includes('descriptor.proto')) continue;
  const raw = buf.slice(d.off, d.off + d.len);
  const f = pf(raw, 0, raw.length);
  const pkg = f.find(x => x.fn === 2)?.v?.toString() || '';
  out.push(`// ===== ${d.name}${pkg ? '  (package ' + pkg + ')' : ''} =====`);
  for (const mt of f.filter(x => x.fn === 4)) dumpMsg(mt.v, '');
  for (const en of f.filter(x => x.fn === 5)) {
    const ef = pf(en.v, 0, en.v.length);
    out.push(`enum ${ef.find(x => x.fn === 1)?.v?.toString()} {`);
    for (const v of ef.filter(x => x.fn === 2)) {
      const vf = pf(v.v, 0, v.v.length);
      out.push(`  ${vf.find(x => x.fn === 1)?.v?.toString()} = ${vf.find(x => x.fn === 2)?.v};`);
    }
    out.push('}');
  }
  out.push('');
}
fs.writeFileSync(path.join(dir, 'live-protocol.proto'), out.join('\n'));
console.log('已写入 live-protocol.proto，行数:', out.length);
