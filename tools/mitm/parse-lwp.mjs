/**
 * LWP 协议解析器
 * 帧格式：
 *   请求  LWP <uri>\n[<key>:<value>\n]*\n[<body>]
 *   响应  <code>\n[<key>:<value>\n]*\n[<body>]
 * 头部终止于空行；有 len 时 body 长度已知。
 *
 * 用法: node parse-lwp.mjs <目录>
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const dir = process.argv[2];
if (!dir) { console.error('用法: node parse-lwp.mjs <conn目录>'); process.exit(1); }

/** 从 buffer 解一帧，返回 {frame, consumed} 或 null */
function parseFrame(buf, offset = 0) {
  // 找到头部结束位置（\n\n）
  let headerEnd = -1;
  for (let i = offset; i < buf.length - 1; i++) {
    if (buf[i] === 0x0a && buf[i + 1] === 0x0a) { headerEnd = i; break; }
  }
  if (headerEnd === -1) return null;

  const headerText = buf.slice(offset, headerEnd).toString('latin1');
  const lines = headerText.split('\n');
  const first = lines[0] ?? '';

  const isRequest = first.startsWith('LWP ');
  const isResponse = /^\d{3}$/.test(first);
  if (!isRequest && !isResponse) return null;

  const headers = {};
  for (const line of lines.slice(1)) {
    const i = line.indexOf(':');
    if (i > 0) headers[line.slice(0, i)] = line.slice(i + 1);
  }

  const len = headers.len !== undefined ? Number(headers.len) : null;
  const bodyStart = headerEnd + 2;
  const bodyEnd = len !== null ? bodyStart + len : bodyStart;
  if (len !== null && bodyEnd > buf.length) return null; // 不完整

  return {
    frame: {
      kind: isRequest ? 'req' : 'res',
      uri: isRequest ? first.slice(4) : null,
      code: isRequest ? null : Number(first),
      headers,
      bodyLen: len ?? (bodyEnd - bodyStart),
      body: buf.slice(bodyStart, Math.min(bodyEnd, buf.length)),
    },
    consumed: bodyEnd - offset,
  };
}

/** 连续解析一个文件里的所有帧 */
function parseAll(buf) {
  const frames = [];
  let off = 0;
  for (let guard = 0; guard < 10000 && off < buf.length; guard++) {
    // 跳过前导空白/二进制残片
    const r = parseFrame(buf, off);
    if (!r) {
      // 尝试找下一个 "LWP " 或 "200\n"
      const s = buf.indexOf('LWP ', off + 1);
      const t = buf.indexOf(Buffer.from([0x32, 0x30, 0x30, 0x0a]), off + 1); // "200\n"
      const next = [s, t].filter((x) => x > off).sort((a, b) => a - b)[0];
      if (next === undefined) break;
      off = next;
      continue;
    }
    frames.push(r.frame);
    off += r.consumed;
    if (r.consumed <= 0) break;
  }
  return frames;
}

const files = readdirSync(dir).filter((f) => f.endsWith('.bin')).sort();
const out = [];
for (const f of files) {
  const buf = readFileSync(join(dir, f));
  const frames = parseAll(buf);
  for (const fr of frames) out.push({ file: f, ...fr });
}

console.log(`解析到 ${out.length} 帧\n`);
const byUri = {};
for (const f of out) {
  if (f.kind === 'req') byUri[f.uri] = (byUri[f.uri] || 0) + 1;
}
console.log('=== 请求 URI ===');
for (const [u, c] of Object.entries(byUri).sort((a, b) => b[1] - a[1])) {
  console.log(`  ${c}x  ${u}`);
}

console.log('\n=== 帧详情（前 20 条请求）===');
out.filter((f) => f.kind === 'req').slice(0, 20).forEach((f) => {
  console.log(`\n[${f.file}] ${f.uri}`);
  console.log('  headers:', JSON.stringify(f.headers));
  if (f.bodyLen) {
    const isJson = /^[[{]/.test(f.body.toString('utf8'));
    console.log(`  body(${f.bodyLen}B)`, isJson ? f.body.toString('utf8').slice(0, 300) : '(binary) ' + f.body.slice(0, 32).toString('hex'));
  }
});
