/**
 * IDLSend/send 请求体构造器
 *
 * 基于真实抓包（0067-c2s.bin，240 字节）逐字节还原：
 *
 *   89 01                          外层长度 varint（= 后续主段长度）
 *   a8 <8B cid>                    cid 短码（如 "VaXHx2W@"，8 字节）
 *   02
 *   ab <11B uid>                   发送者 uid
 *   03 01 04 01 05                 固定
 *   83 01 01 02                    固定
 *   81 01 <len> <UTF-8 正文>       正文段
 *   07 90 06 01 07                 固定
 *   83 <扩展字段…>                   customUnreadCountType 等
 *   a3 "oid" a9 <orgId>            oid / orgId
 *   08 b7 <23B 会话名>              会话名
 *   12 83 01 cd 02 32 02          固定
 *   da 00 20 <JSON>                {"empVer":0,"orgId":"..."}
 *   04
 *   da 00 2f <资源ID 47B>          附件占位
 */

/** Gaea 字符串：0x80 | (32 + byteLen) */
function gs(s: string): Buffer {
  const d = Buffer.from(s, 'utf8');
  return Buffer.concat([Buffer.from([0x80 | (32 + d.length)]), d]);
}

/** 变长整数（1~3 字节） */
function varint(v: number): Buffer {
  const out: number[] = [];
  let n = v;
  while (n >= 0x80) { out.push((n & 0x7f) | 0x80); n >>>= 7; }
  out.push(n);
  return Buffer.from(out);
}

/** 正文段：81 01 + 长度标记 + UTF-8 */
function textSegment(text: string): Buffer {
  const d = Buffer.from(text, 'utf8');
  const n = d.length;
  // 标记 = 0x80 | (32 + n)，n ≤ 62 时单字节
  const marker = n <= 62
    ? Buffer.from([0x80 | (32 + n)])
    : Buffer.concat([Buffer.from([0xda, 0x00]), varint(n)]);
  return Buffer.concat([Buffer.from([0x81, 0x01]), marker, d]);
}

export interface SendParams {
  /** 会话短码，抓包中的 8 字符串，如 "VaXHx2W@" */
  cid: string;
  /** 发送者 uid，如 "79553200501" */
  uid: string;
  /** 组织 id */
  orgId: string;
  /** 会话名 */
  convName: string;
  /** 消息正文 */
  text: string;
}

/** 资源占位（抓包中的固定值，非附件消息时服务端忽略） */
const RES_PLACEHOLDER = Buffer.from('@lQLPD3ecCjIZo5XNAyDNAyCwgmhRm90Cb5sKmBipiF_VAA', 'latin1');

/**
 * 构造 /r/IDLSend/send 的请求体。
 *
 * 外层 89 01 的长度 = 紧随其后、到「会话名前」为止的字节数，
 * 抓包中为 137（body 总长 240）。
 */
export function buildSendBody(p: SendParams): Buffer {
  const cid = Buffer.from(p.cid, 'latin1');
  if (cid.length > 62) throw new Error(`cid 过长: ${cid.length}`);

  // oid / orgId / 会话名 —— 计入外层长度
  const covered = Buffer.concat([
    gs('oid'), gs(p.orgId),
    Buffer.from([0x08]), gs(p.convName),
  ]);
  // 会话名之后 —— 不计入
  const rest = Buffer.concat([
    Buffer.from([0x12, 0x83, 0x01, 0xcd, 0x02, 0x32, 0x02]),
    Buffer.from([0xda, 0x00, 0x20]),
    Buffer.from(JSON.stringify({ empVer: 0, orgId: p.orgId }), 'utf8'),
    Buffer.from([0x04, 0xda, 0x00, 0x2f]),
    RES_PLACEHOLDER,
  ]);

  const main = Buffer.concat([
    // cid
    Buffer.from([0x80 | (32 + cid.length)]), cid,
    Buffer.from([0x02]),
    gs(p.uid),
    Buffer.from([0x03, 0x01, 0x04, 0x01, 0x05]),
    Buffer.from([0x83, 0x01, 0x01, 0x02]),
    textSegment(p.text),
    Buffer.from([0x07, 0x90, 0x06, 0x01, 0x07]),
    Buffer.from([0x83]),
    gs('customUnreadCountType'), gs('edu_guardian'),
    gs('customUnreadTotalCount'), gs('1'),
  ]);

  // 外层长度覆盖「主内容 + oid/orgId/会话名」，但不含 cid 本身（抓包样本 137）
  const outer = varint(main.length + covered.length - cid.length);
  return Buffer.concat([outer, main, covered, rest]);
}

/** 抓包样本（自检用） */
export function paramsFromSample(): SendParams {
  return { cid: 'VaXHx2W@', uid: '79553200501', orgId: '880519069', convName: '钉钉帕鲁(班主任)', text: '测试' };
}