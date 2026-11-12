/**
 * listMessagesPagination 响应解析
 *
 * 响应是 Gaea 二进制（无 JSON），消息正文以 UTF-8 文本块散布其中，
 * 前后有结构字节。此处用启发式提取文本块（中文/可读串）。
 *
 * 已知局限：sender/时间戳的 Gaea 字段号未破解，先用文本块近似。
 * （/s/sync 推送是 JSON 格式，走 sync-parser 拿完整字段。）
 */
import type { Message } from '@teletalk/shared';

/** 从 V1 响应提取消息文本块 */
export function parseMessagePage(body: Buffer, dialogId: string): Message[] {
  const out: Message[] = [];
  const seen = new Set<string>();

  // 滑窗提取 UTF-8 可读块：连续 ≥8 个「中文/字母数字/常用标点空白」
  const s = body;
  let i = 0;
  let start = -1;
  const flush = (end: number) => {
    if (start < 0) return;
    const chunk = s.subarray(start, end);
    const text = chunk.toString('utf8')
      .replace(/^[^一-龥A-Za-z0-9]+/, '')
      .replace(/^[A-Za-z](?=[一-龥])/, '')
      .trim();
    if (text.length >= 4 && !seen.has(text)) {
      seen.add(text);
      out.push({
        id: dialogId + ':' + start,
        dialogId,
        senderId: '',
        text,
        createdAt: Date.now(),
        kind: 'text',
        self: false,
      });
    }
    start = -1;
  };

  while (i < s.length) {
    // 按 3 字节窗口判断是否「文本字符」（UTF-8 中文 3B 或 ASCII 可打印）
    let ok = false;
    const c = s[i]!;
    if (c >= 0x20 && c < 0x7f) ok = true;                 // ASCII 可打印
    else if (c >= 0xe4 && c <= 0xe9 && i + 2 < s.length) { // CJK 常用区 e4-e9
      const b1 = s[i + 1]!, b2 = s[i + 2]!;
      if ((b1 & 0xc0) === 0x80 && (b2 & 0xc0) === 0x80) { i += 3; if (start < 0) start = i - 3; continue; }
    }
    if (ok) {
      // 常用中文标点（，。！？、：；（）"" 空白 换行）
      if (start < 0) start = i;
      i++;
    } else {
      flush(i);
      i++;
    }
  }
  flush(s.length);

  // 过滤噪声：纯数字/过短/URL 字段名
  return out.filter((m) =>
    /[一-龥]/.test(m.text) &&
    m.text.replace(/[一-龥]/g, '').length < m.text.length * 0.7 &&
    !/^(true|false|null)$/.test(m.text)
  );
}
