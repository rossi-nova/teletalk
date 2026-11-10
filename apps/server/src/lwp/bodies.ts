/**
 * 请求体构造器（仅实现已用抓包验证的部分）
 *
 * 已确认规律：
 *   字符串 ID 字段 = [0x80 | (32 + byteLen)] + utf8 bytes
 *     例：id "69712715263"（11 字节）→ 0xab + 数据
 *         id "3249641022" （10 字节）→ 0xaa + 数据
 *
 * 未确认：外层长度前缀（如 0x91）的语义，因此构造器只产出内层字段，
 *         调用方可自行拼接外层。
 */

/** 字符串 ID 字段 */
export function strId(id: string): Buffer {
  const data = Buffer.from(id, 'utf8');
  if (data.length > 95) {
    throw new Error(`ID 过长（${data.length} 字节），超出已验证范围 95`);
  }
  return Buffer.concat([Buffer.from([0x80 | (32 + data.length)]), data]);
}

/** 数值字段：0xcf + 大端字节 */
export function numField(bytes: number[]): Buffer {
  return Buffer.concat([Buffer.from([0xcf]), Buffer.from(bytes)]);
}

/** 拼接多个字段 */
export function concat(...parts: Buffer[]): Buffer {
  return Buffer.concat(parts);
}
