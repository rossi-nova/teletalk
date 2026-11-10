/** protobuf 递归解码，带覆盖率校验 */
export function decode(buf, depth = 0) {
  const fields = [];
  let p = 0;
  const rv = () => { let v = 0, s = 0, c; do { c = buf[p++]; if (c === undefined) throw 0; v += (c & 0x7f) * 2 ** s; s += 7; } while (c & 0x80 && s < 64); return v; };
  while (p < buf.length) {
    const st = p;
    let tag;
    try { tag = rv(); } catch { p = st; break; }
    const fn = tag >>> 3, wt = tag & 7;
    if (fn === 0 || fn > 100000) { p = st; break; }
    try {
      if (wt === 0) fields.push({ f: fn, k: 'varint', v: rv() });
      else if (wt === 2) {
        const len = rv();
        if (st + len > buf.length || p + len > buf.length) { p = st; break; }
        const chunk = buf.slice(p, p + len);
        p += len;
        // 尝试递归，要求覆盖全部字节且字段合法
        let sub = null;
        if (depth < 8 && chunk.length >= 3) {
          const r = decode(chunk, depth + 1);
          if (r.fields.length && r.consumed === chunk.length && r.fields.every(x => x.f <= 1000)) sub = r.fields;
        }
        if (sub) fields.push({ f: fn, k: 'msg', len, v: sub });
        else {
          const s = chunk.toString('utf8');
          const printable = chunk.every(x => x !== 0) && /^[\x09\x0a\x0d\x20-\x7e\u4e00-\u9fa5\u3000-\u303f\uff00-\uffef]*$/u.test(s);
          fields.push({ f: fn, k: printable ? 'str' : 'bin', len, v: printable ? s : chunk.toString('hex').slice(0, 64) });
        }
      }
      else if (wt === 5) { fields.push({ f: fn, k: 'f32', v: buf.readUInt32LE(p) }); p += 4; }
      else if (wt === 1) { fields.push({ f: fn, k: 'f64', v: buf.readBigUInt64LE(p).toString() }); p += 8; }
      else { p = st; break; }
    } catch { p = st; break; }
  }
  return { fields, consumed: p, total: buf.length };
}

export function render(r, ind = '') {
  const out = [];
  for (const x of r.fields) {
    if (x.k === 'msg') {
      out.push(`${ind}f${x.f} msg(${x.len}) {`);
      out.push(render({ fields: x.v }, ind + '  '));
      out.push(`${ind}}`);
    } else {
      const v = typeof x.v === 'string' ? JSON.stringify(x.v) : x.v;
      out.push(`${ind}f${x.f} ${x.k} = ${v}`);
    }
  }
  return out.join('\n');
}
