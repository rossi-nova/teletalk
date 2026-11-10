/**
 * IDLSend/send 报文编解码
 *
 * 结构（实测 12 条样本）：
 *   02 81 01 <marker> <正文 UTF-8> 07 90 06 01 07 ...
 *
 * marker:
 *   短消息（≤95B） 单字节 0xA0 + len
 *   长消息（>95B） 三字节，首字节 0xDA，不编码精确长度
 *
 * 正文边界靠尾部固定串 07 90 06 01 07 定位。
 */
const PREFIX = Buffer.from([0x81, 0x01]);
const TAIL = Buffer.from([0x07, 0x90, 0x06, 0x01, 0x07]);
const MARKER_BASE = 0xa0;
const MARKER_LONG = 0xda;

/** 编码长度标记 */
export function encodeMarker(len: number): Buffer {
  if (len <= 95) return Buffer.from([MARKER_BASE + len]);
  // 长消息：3 字节，中间字节承载长度高位（实测 da 00/01/02/03/04 随长度递增）
  const hi = Math.min(255, Math.floor(len / 256));
  return Buffer.from([MARKER_LONG, hi, 0xf9]);
}

/** 解析 marker 长度（返回占用的字节数） */
export function markerSize(first: number): number {
  return first === MARKER_LONG ? 3 : 1;
}

/** 从 body 提取正文 */
export function extractText(body: Buffer): string | null {
  const i = body.indexOf(PREFIX);
  if (i < 0) return null;
  const t = body.indexOf(TAIL, i);
  if (t < 0) return null;
  const region = body.slice(i + PREFIX.length, t);
  if (!region.length) return '';
  const skip = markerSize(region[0]!);
  return region.slice(skip).toString('utf8');
}

export interface SendPayload {
  text: string;
  cidHint?: string;
  senderHint?: string;
  orgId?: string;
}

/** 从 body 提取结构化字段 */
export function inspect(body: Buffer): SendPayload {
  const out: SendPayload = { text: extractText(body) ?? '' };

  const cidM = body.slice(2, 12).toString('latin1').match(/[\x20-\x7e]+/);
  if (cidM) out.cidHint = cidM[0];

  const uidM = body.slice(10, 30).toString('latin1').match(/\d{8,15}/);
  if (uidM) out.senderHint = uidM[0];

  const orgM = body.toString('utf8').match(/"orgId":"(\d+)"/);
  if (orgM) out.orgId = orgM[1];

  return out;
}
