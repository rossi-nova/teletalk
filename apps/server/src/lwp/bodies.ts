/**
 * 请求体构造器（基于抓包实测）
 *
 * Gaea 二进制编码（非标准 protobuf）：
 *   0xcf + 4B 大端 uint32 → 数字
 *   0x80|(32+n) + n ASCII → 字符串
 *   varint（最高位续位）  → 标签/长度
 *
 * 关键实测结论：
 *   - listNewest 空 body 返回 200 + 0xC0（空列表）
 *   - listMessagesPaginationV2 需要完整结构（含 lastMessageId 字段）
 *   - 响应 gzip 压缩（1f 8b 08），由 frame 层解压
 */

/** 字符串字段：0x80 | (32 + byteLen) */
export function strField(s: string): Buffer {
  const data = Buffer.from(s, 'utf8');
  if (data.length > 62) throw new Error(`字符串过长（${data.length} > 62）`);
  return Buffer.concat([Buffer.from([0x80 | (32 + data.length)]), data]);
}

/** 数字字段：0xcf + 4B 大端 */
export function numField(v: number): Buffer {
  const b = Buffer.alloc(5);
  b[0] = 0xcf;
  b.writeUInt32BE(v >>> 0, 1);
  return b;
}

/** varint */
export function varint(v: number): Buffer {
  const out: number[] = [];
  let n = v >>> 0;
  while (n >= 0x80) { out.push((n & 0x7f) | 0x80); n >>>= 7; }
  out.push(n);
  return Buffer.from(out);
}

/** 字符串 ID 字段（别名，语义更明确；同 strField） */
export function strId(id: string): Buffer {
  return strField(id);
}

/** 十六进制字面量（未破解字段直接用原样） */
export function raw(hex: string): Buffer {
  return Buffer.from(hex.replace(/\s/g, ''), 'hex');
}

export function concat(...parts: Buffer[]): Buffer {
  return Buffer.concat(parts);
}

// ──── 已验证的接口 ────

/**
 * listNewest —— 会话列表
 * 空 body 亦可（返回 0xC0 空数组）；
 * 抓包参数 = 「取 1 条高亮会话」
 */
export function listNewestBody(): Buffer {
  return Buffer.alloc(0);
}

/**
 * listMessagesPaginationV2 —— 历史消息分页
 *
 * 实测抓包结构（60 字节）：
 *   86 01                                  ← 外层 varint 134
 *   ab <cid 11>                            ← conversationId
 *   02                                     ← 常量
 *   c2 03                                  ← 嵌套 3 字节 varint 标签
 *   cf 00 00 01 9f                         ← num 415（页大小元数据）
 *   61                                     ← 常量
 *   fa e9 05                               ← 游标 varint（时间基）
 *   04                                     ← 常量
 *   c2 05                                  ← 嵌套 5 字节标签
 *   1d | 1e                                ← 方向（1d=向后 / 1e=向前）
 *   06                                     ← 常量
 *   bc <lastId 28>                         ← "3-{cid}-{ts}"
 *
 * 注意：不同 cid 的尾段长度会变，需动态算外层 varint。
 */
export function listMessagesBody(params: {
  cid: string;
  limit?: number;
  cursor?: number;
  direction?: 'back' | 'forward';
  lastMessageId?: string;
}): Buffer {
  const { cid, limit = 415, cursor = 0, direction = 'back', lastMessageId } = params;
  const dir = direction === 'forward' ? 0x1e : 0x1d;
  const lastId = lastMessageId ?? `3-${cid}-0`;

  const inner = concat(
    strField(cid),
    raw('02'),
    varint(450),
    numField(limit),
    raw('61'),
    varint(cursor),
    raw('04'),
    varint(706),
    Buffer.from([dir]),
    raw('06'),
    strField(lastId),
  );
  return concat(varint(inner.length + 74), inner);
}

/**
 * listMessagesPagination（V1，轻量版）
 * 抓包结构：ab <cid> c2 cf 00 00 01 9f <cursor 3B> 1d
 */
export function listMessagesBodyV1(params: { cid: string; limit?: number; cursor?: number }): Buffer {
  const { cid, limit = 415, cursor = 0 } = params;
  return concat(strField(cid), raw('c2'), numField(limit), varint(cursor), raw('1d'));
}
