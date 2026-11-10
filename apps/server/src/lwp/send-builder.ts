/**
 * IDLSend/send 请求体构造器
 *
 * 基于真实抓包（0067-c2s.bin，240 字节）逐段还原。
 * 结构：
 *   [固定头] [cid] [固定] [uid] [固定序列] [81 01][marker][正文][固定尾]
 *   [扩展键值] [oid][orgId] [会话名] [固定] [marker(32)][JSON] [marker(47)][资源ID]
 *
 * 可变字段：cid、uid、orgId、会话名、正文。其余按抓包样本固化。
 */

/** 追加带 0x80|(32+len) 前缀的字符串（实测规律） */
function prefixed(prefix: number, data: Buffer): Buffer {
  return Buffer.concat([Buffer.from([prefix | (32 + data.length)]), data]);
}

/** 正文段：81 01 + marker + utf8 */
export function textSegment(text: string): Buffer {
  const data = Buffer.from(text, 'utf8');
  const len = data.length;
  let marker: Buffer;
  if (len <= 95) {
    marker = Buffer.from([0xa0 + len]);
  } else {
    // 长消息：3 字节 —— 0xDA + 高位 + 低 8 位（实测 228→e4, 761→f9, 1009→f1, 1263→ef）
    marker = Buffer.from([0xda, Math.min(255, Math.floor(len / 256)), len & 0xff]);
  }
  return Buffer.concat([Buffer.from([0x81, 0x01]), marker, data]);
}

export interface SendParams {
  /** 会话 id，抓包中的 9 字符片段，如 "aXHx2W@" */
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

/** 构造 /r/IDLSend/send 的请求体 */
export function buildSendBody(p: SendParams): Buffer {
  const cid = Buffer.from(p.cid, 'latin1');
  const uid = Buffer.from(p.uid, 'utf8');
  const orgId = Buffer.from(p.orgId, 'utf8');
  const convName = Buffer.from(p.convName, 'utf8');

  const head = Buffer.from('8901', 'hex');
  // 实测：cid 为 7 字节时前缀固定为 a8 56（0x56 = 86）
  // 该字段编码规律尚未完全破解，此处对 7 字节 cid 使用样本常量，
  // 其他长度沿用 0x80|(32+len) 的近似规则。
  const cidPrefix = cid.length === 7
    ? Buffer.from([0xa8, 0x56])
    : Buffer.from([0xa8, 0x80 | (32 + cid.length)]);

  const fixed1 = Buffer.from('02', 'hex');
  const uidField = prefixed(0xa0, uid);
  const fixed2 = Buffer.from('0301040105', 'hex');
  const fixed3 = Buffer.from('83010102', 'hex');

  const textSeg = textSegment(p.text);

  const fixed4 = Buffer.from('079006010783', 'hex');
  // 扩展字段统一用 0x80|(32+len) 前缀
  const extKey1 = prefixed(0x80, Buffer.from('customUnreadCountType'));
  const extVal1 = prefixed(0x80, Buffer.from('edu_guardian'));
  const extKey2 = prefixed(0x80, Buffer.from('customUnreadTotalCount'));
  const extVal2 = prefixed(0xa0, Buffer.from('1'));
  const oidKey = prefixed(0xa0, Buffer.from('oid'));
  const oidVal = prefixed(0x80, orgId);

  const fixed5 = Buffer.from('08', 'hex');
  const nameField = prefixed(0x80, convName);
  const fixed6 = Buffer.from('128301cd023202', 'hex');

  const jsonObj = Buffer.from(JSON.stringify({ empVer: 0, orgId: p.orgId }), 'utf8');
  const jsonSeg = Buffer.concat([Buffer.from([0xda, 0x00, 0x20]), jsonObj]);

  const fixed7 = Buffer.from('04', 'hex');
  // 资源占位：抓包中为 47 字节的 @lQLP... 串
  const resPlaceholder = Buffer.from('@lQLPD3ecCjIZo5XNAyDNAyCwgmhRm90Cb5sKmBipiF_VAA', 'latin1');
  const resSeg = Buffer.concat([Buffer.from([0xda, 0x00, 0x2f]), resPlaceholder]);

  return Buffer.concat([
    head, cidPrefix, cid,
    fixed1, uidField, fixed2, fixed3,
    textSeg,
    fixed4,
    extKey1, extVal1, extKey2, extVal2,
    oidKey, oidVal,
    fixed5, nameField,
    fixed6,
    jsonSeg,
    fixed7,
    resSeg,
  ]);
}

/** 从抓包样本还原参数（用于自检） */
export function paramsFromSample(): SendParams {
  return {
    cid: 'aXHx2W@',
    uid: '79553200501',
    orgId: '880519069',
    convName: '钉钉帕鲁(班主任)',
    text: '测试',
  };
}
