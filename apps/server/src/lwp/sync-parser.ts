/**
 * /s/sync 推送解析
 *
 * 消息体是嵌在二进制里的 JSON 片段，形如：
 *   {"senderId":290811940,"conversationId":"78496531195","messageId":27675089641600,
 *    "content":{"contentType":1,"textContent":{"text":"..."}}}
 *
 * 会话元信息以 key\u0000value 形式跟在后面：
 *   \u0000openConversationId\u0000cid...\u0000sourceNick\u0000滑双莹 ...
 */

export interface SyncedMessage {
  senderId: string;
  conversationId: string;
  openConversationId?: string;
  messageId: string;
  text: string;
  senderNick?: string;
  kind: 'text' | 'unknown';
}

/** 从推送 body 中提取所有消息 */
export function parseSync(body: Buffer): SyncedMessage[] {
  const out: SyncedMessage[] = [];
  const s = body.toString('utf8');

  // 消息 JSON：以 {"senderId": 开头
  const re = /\{"senderId":(\d+),"conversationId":"([^"]+)","messageId":(\d+)[\s\S]{0,200}?"content":\{([\s\S]*?)\}\}/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(s))) {
    const [, senderId, conversationId, messageId, contentRaw] = m;
    const textM = contentRaw!.match(/"textContent":\{"text":"((?:[^"\\]|\\.)*)"/);
    if (!textM) continue;

    let text = '';
    try {
      text = JSON.parse(`"${textM[1]}"`);
    } catch {
      text = textM[1]!;
    }

    out.push({
      senderId: senderId!,
      conversationId: conversationId!,
      messageId: messageId!,
      text,
      kind: 'text',
    });
  }

  // 会话与昵称：key\u0000value 对
  const kv = extractKv(s);
  for (const msg of out) {
    msg.senderNick = kv.get('sourceNick') ?? undefined;
    msg.openConversationId = kv.get('openConversationId');
  }
  return out;
}

/** 提取 \u0000key\u0000value 形式的键值对 */
function extractKv(s: string): Map<string, string> {
  const map = new Map<string, string>();
  const known = ['sourceNick', 'openConversationId', 'sourceSenderId', 'sendMsgUUID', 'oid'];
  for (const k of known) {
    const re = new RegExp(`\u0000${k}\u0000([^\u0000]{1,80})`);
    const m = s.match(re);
    if (m) map.set(k, m[1]!.trim());
  }
  return map;
}
