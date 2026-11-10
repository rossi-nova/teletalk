/**
 * 钉钉 IDLSend/send 报文编解码器
 * 已确认格式：02 81 01 | [0xA0+len] | 正文 UTF-8 | 07 90 06 01 07 ...
 */
import { readFileSync } from 'node:fs';

const MARKER_BASE = 0xa0;

/** 解析长度标记（长度 ≤ 95 时为单字节 0xA0+len） */
export function decodeLenMarker(buf, p) {
  const first = buf[p];
  if (first >= MARKER_BASE && first < MARKER_BASE + 96) {
    return { len: first - MARKER_BASE, consumed: 1 };
  }
  return null;
}

/** 从 body 提取消息正文（用尾部固定串定位，长短消息通用） */
export function extractText(body) {
  const i = body.indexOf(Buffer.from([0x81, 0x01]));
  if (i < 0) return null;
  const tail = Buffer.from([0x07, 0x90, 0x06, 0x01, 0x07]);
  const t = body.indexOf(tail, i);
  if (t < 0) return null;
  const region = body.slice(i + 2, t);
  // marker：首字节 0xDA 时占 2 字节，否则 1 字节
  const markerLen = region[0] === 0xda ? 3 : 1;
  return region.slice(markerLen).toString('utf8');
}

/** 提取可读字段 */
export function inspect(body) {
  const out = { text: extractText(body) };
  const s = body.toString('utf8');
  const cidM = body.slice(2, 12).toString('latin1').match(/[\x20-\x7e]+/);
  if (cidM) out.cidHint = cidM[0];
  const uidM = body.slice(10, 30).toString('latin1').match(/(\d{8,15})/);
  if (uidM) out.senderHint = uidM[1];
  const orgM = s.match(/"orgId":"(\d+)"/);
  if (orgM) out.orgId = orgM[1];
  const nameM = s.match(/\u0008[^\u0000]{0,3}([\u4e00-\u9fa5A-Za-z0-9()（）]{2,30})/u);
  if (nameM) out.convNameHint = nameM[1];
  return out;
}

/** 遍历文件里的 LWP 帧 */
export function* frames(buf) {
  let off = 0;
  for (let g = 0; g < 5000 && off < buf.length - 1; g++) {
    const isLwp = buf.slice(off, off + 4).toString('latin1') === 'LWP ';
    const isRes = buf.slice(off, off + 4).toString('latin1') === '200\n';
    if (!isLwp && !isRes) {
      const a = buf.indexOf('LWP ', off + 1);
      const r = buf.indexOf(Buffer.from('200\n'), off + 1);
      const next = [a, r].filter((x) => x > off).sort((x, y) => x - y)[0];
      if (next === undefined) return;
      off = next;
      continue;
    }
    const he = buf.indexOf('\n\n', off);
    if (he < 0) return;
    const head = buf.slice(off, he).toString('latin1');
    const hdr = {};
    for (const l of head.split('\n').slice(1)) {
      const i = l.indexOf(':');
      if (i > 0) hdr[l.slice(0, i)] = l.slice(i + 1);
    }
    const len = Number(hdr.len || 0);
    yield {
      isReq: isLwp,
      uri: isLwp ? head.split('\n')[0].slice(4) : null,
      hdr,
      body: buf.slice(he + 2, he + 2 + len),
    };
    off = he + 2 + len;
  }
}

// CLI
const file = process.argv[2];
if (file) {
  const buf = readFileSync(file);
  let n = 0;
  for (const f of frames(buf)) {
    if (f.isReq && f.uri && f.uri.includes('IDLSend/send')) {
      console.log(JSON.stringify({ mid: f.hdr.mid, ...inspect(f.body) }, null, 1));
      n++;
    }
  }
  if (!n) console.log('未找到 IDLSend/send 帧');
}
