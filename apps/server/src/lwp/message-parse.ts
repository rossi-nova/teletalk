/**
 * listMessagesPagination(V1) 响应解析
 *
 * 响应是 Gaea 二进制（非 protobuf），结构：
 *
 *   每条消息以 [0a 00][0c 00][12 <Gaea 数值>] 开头，
 *   其后跟一串 Gaea 长度前缀字符串对（widgetName / convThreadId /
 *   sendMsgUUID / topicGroup / ...），正文在 payload JSON 里（"text":"..."）。
 *   messageId 形如 "3-{cid}-{ts}"，直接出现在块内。
 *
 * 已知限制（接口本身不提供）：
 *   - 没有 senderId / senderNick（senderId 字段恒为空字符串）
 *   - 没有可读时间戳（messageId 的数值段不是 Unix 时间）
 * 能拿到：发送者索引（0x12 后的值，同一人恒定）、正文、messageId、顺序。
 */
import type { Message } from '@teletalk/shared';

/** Gaea 长度前缀字符串 */
function gaeaStr(buf: Buffer, k: number): { s: string; next: number } | null {
  if (k >= buf.length) return null;
  const t = buf[k]!;
  if ((t & 0xc0) !== 0x80) return null;
  const n = (t & 0x3f) - 32;
  if (n <= 0 || n > 62 || k + 1 + n > buf.length) return null;
  return { s: buf.subarray(k + 1, k + 1 + n).toString('utf8'), next: k + 1 + n };
}

/** 消息块起点：0a 00 0c 00 12 */
function findOrigins(b: Buffer): number[] {
  const out: number[] = [];
  for (let k = 0; k + 4 < b.length; k++) {
    if (b[k] === 0x0a && b[k + 1] === 0x00 && b[k + 2] === 0x0c && b[k + 3] === 0x00 && b[k + 4] === 0x12) {
      out.push(k);
    }
  }
  return out;
}

/** 读消息块里的发送者索引（0x12 后的 Gaea 数值） */
function readSenderKey(b: Buffer, origin: number): number {
  const a = origin + 5; // 跳过 12
  if (a + 4 < b.length) {
    if (b[a] === 0xcf) return b.readUInt32BE(a + 1);
    if (b[a] === 0xce) return b.readUInt32BE(a + 1);
    if (b[a] === 0xcd) return b.readUInt16BE(a + 1);
    if (b[a] === 0xcc) return b[a + 1] ?? 0;
  }
  return b[a] ?? 0;
}

const KEY_RE = /^[a-zA-Z_][A-Za-z0-9_]{2,30}$/;
const MSG_ID_RE = /3-\d{8,14}-\d{8,20}/;
const TEXT_RE = /"text":"((?:[^"\\]|\\.)*)"/g;
/** 客户端版本过低时服务端塞的占位文本，剥掉 */
const NOISE = /\[版本过低不支持展示，请升级客户端\]/g;

function unescapeJson(s: string): string {
  try {
    return JSON.parse('"' + s + '"');
  } catch {
    return s;
  }
}

export interface ParsedMessage extends Message {
  /** 发送者稳定索引（同一人恒定；无法还原成真实 uid） */
  senderKey: number;
  /** 原始消息 ID（3-{cid}-{ts}） */
  rawId?: string;
}

/** 解析 V1 历史消息响应 */
export function parseMessagePage(body: Buffer, dialogId: string): ParsedMessage[] {
  const origins = findOrigins(body);
  const u8 = body.toString('utf8');
  const out: ParsedMessage[] = [];

  origins.forEach((o, i) => {
    const end = i + 1 < origins.length ? origins[i + 1]! : body.length;
    const seg = body.subarray(o, Math.min(end, o + 20000));

    // kv 表
    const kv: Record<string, string> = {};
    let k = 0;
    while (k < seg.length) {
      const g = gaeaStr(seg, k);
      if (!g) { k++; continue; }
      if (KEY_RE.test(g.s)) {
        const v = gaeaStr(seg, g.next);
        if (v && v.s.length < 80) { kv[g.s] = v.s; k = v.next; continue; }
      }
      k = g.next;
    }

    // 正文：payload JSON 里的 text 串
    const s = seg.toString('utf8');
    let text = '';
    let m: RegExpExecArray | null;
    TEXT_RE.lastIndex = 0;
    while ((m = TEXT_RE.exec(s))) text += unescapeJson(m[1] ?? '');
    text = text.replace(NOISE, '').trim();
    // 标题与正文同文时会重复一遍（"xxx" + "xxx"），折叠
    const half = text.length / 2;
    if (Number.isInteger(half) && text.slice(0, half) === text.slice(half)) text = text.slice(0, half);

    const rawId = s.match(MSG_ID_RE)?.[0] ?? u8.slice(o, o + 200).match(MSG_ID_RE)?.[0];

    out.push({
      id: rawId ?? `${dialogId}:${o}`,
      dialogId,
      senderId: '',           // 接口不提供
      senderName: undefined,  // 接口不提供
      text,
      createdAt: Date.now(),  // 接口不提供可读时间，按返回顺序近似
      kind: 'text',
      self: false,
      senderKey: readSenderKey(body, o),
      rawId,
    });
  });

  return out.filter((x) => x.text.length > 0);
}
