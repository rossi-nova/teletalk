/**
 * 离线演示：用抓包样本回放，供无凭据时验证网关行为
 */
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { parseFrames } from '../lwp/frame.js';
import { inspect } from '../lwp/message-codec.js';
import type { Message } from '@teletalk/shared';

export interface ReplayResult {
  frames: number;
  messages: Message[];
}

/** 从抓包目录回放 IDLSend 帧，产出结构化消息 */
export function replayMessages(dir: string): ReplayResult {
  let frames = 0;
  const messages: Message[] = [];

  for (const f of readdirSync(dir).filter((x) => x.endsWith('.bin'))) {
    const { frames: fs_ } = parseFrames(readFileSync(join(dir, f)));
    for (const fr of fs_) {
      frames++;
      if (fr.kind !== 'req' || fr.uri !== '/r/IDLSend/send') continue;
      const p = inspect(fr.body);
      messages.push({
        id: fr.headers.mid ?? '',
        dialogId: p.cidHint ?? '',
        senderId: p.senderHint ?? '',
        text: p.text,
        createdAt: Date.now(),
        kind: 'text',
        self: true,
      });
    }
  }
  return { frames, messages };
}
