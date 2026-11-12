/**
 * 会话详情解析
 *
 * 数据源：/r/IDLConversation/getById 响应（Gaea 二进制，client 层已解压）
 * 编码与请求体同族：
 *   0x80|(32+len) + len 字节 = 字符串（key 与 value 都用这个）
 *   0xcf + 4B 大端            = 数字
 *
 * 实测：连续的 字符串对 构成 kv 表：
 *   a8 "deptName" be "长丰县北城世纪城学校" ...
 */
import type { Dialog } from '@teletalk/shared';

export interface Member {
  uid: string;
  nick: string;
}

export interface DialogDetail {
  id: string;
  title: string;
  type: 'single' | 'group';
  openConversationId?: string;
  members: Member[];
  groupAdmins: string[];
  cspaceId?: string;
  orgId?: string;
}

/** 从偏移处读一个 Gaea 字符串；失败返回 null */
function readStr(b: Buffer, i: number): { s: string; next: number } | null {
  if (i >= b.length) return null;
  const t = b[i]!;
  if ((t & 0xc0) !== 0x80) return null;
  const n = (t & 0x3f) - 32;
  if (n <= 0 || n > 62 || i + 1 + n > b.length) return null;
  return { s: b.subarray(i + 1, i + 1 + n).toString('utf8'), next: i + 1 + n };
}

/**
 * 提取响应里的全部 kv 对（连续 字符串 字符串 序列）
 * 仅保留「key 是常见 camelCase/snake_case 标识符」的对，过滤正文噪声
 */
export function extractKvPairs(body: Buffer): Map<string, string> {
  const out = new Map<string, string>();
  const b = body;
  let i = 0;
  while (i < b.length) {
    const k = readStr(b, i);
    if (!k) { i++; continue; }
    // key 必须像标识符
    if (!/^[A-Za-z_][A-Za-z0-9_]{0,30}$/.test(k.s)) { i = k.next; continue; }
    const v = readStr(b, k.next);
    if (v && v.s.length > 0 && v.s.length < 200) {
      out.set(k.s, v.s);
      i = v.next;
      continue;
    }
    i = k.next;
  }
  return out;
}

/** 解析会话详情 */
export function parseDialogDetail(body: Buffer, knownId?: string): DialogDetail | null {
  const kv = extractKvPairs(body);
  const s = body.toString('utf8');

  const id = knownId ?? kv.get('openConversationId');
  const title =
    kv.get('deptName')?.replace(/^(省|市|县|区)+/, '') ||
    kv.get('convTitle') || kv.get('title') ||
    // 群聊场景：找 group-{id}@ 之外的第一个中文串
    (s.match(/[一-龥][一-龥A-Za-z0-9（）()]{1,15}/) ?? [])[0];
  if (!id || !title) return null;

  // 成员：[{"uId":"528523050","nick":"张永"},...]（JSON 片段）
  const members: Member[] = [];
  const memberRe = /\{"uId":"(\d+)","(?:mediaId":"[^"]*",)?"?nick"?:?"?([^"]*)"?\}/g;
  let mm: RegExpExecArray | null;
  while ((mm = memberRe.exec(s))) members.push({ uid: mm[1]!, nick: mm[2]! });

  // 群管理员（数字数组）
  const adminM = s.match(/\[([\d,]{5,})\]/);
  const groupAdmins = adminM ? adminM[1]!.split(',') : [];

  const isGroup = /group-\d+@/.test(s) || kv.has('groupAdmins') || members.length > 2;

  return {
    id,
    title,
    type: isGroup ? 'group' : 'single',
    openConversationId: kv.get('openConversationId'),
    members,
    groupAdmins,
    cspaceId: kv.get('cSpaceId') ?? kv.get('newCSpaceIdIM'),
    orgId: kv.get('org_id'),
  };
}

/** 转网关 DTO */
export function toDialog(d: DialogDetail): Dialog {
  return {
    id: d.id,
    title: d.title,
    type: d.type,
    unreadCount: 0,
    updatedAt: Date.now(),
  };
}

/** 最近一条消息摘要（kv 表里语义不稳定的字段，先给标题兜底） */
export function parseLastMessageSnippet(body: Buffer): string | undefined {
  const s = body.toString('utf8');
  // 温馨提示 类通知正文：中文长串
  const m = s.match(/[一-龥][一-龥，。、！？：；""''（）\s]{8,60}/);
  return m?.[0]?.trim();
}

/**
 * 从 listNewest 响应提取会话 ID 列表
 * 空结果：单字节 0xC0
 */
export function extractConvIds(body: Buffer): string[] {
  if (body.length <= 1) return [];
  const s = body.toString('latin1');
  const ids = new Set<string>();
  const re = /(?:^|[^\d])(\d{8,14})(?=[^\d]|$)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(s))) ids.add(m[1]!);
  return [...ids];
}

/**
 * 种子会话 ID（来自抓包中会话类请求的 cid，服务端已验证存在）
 * listNewest 返回空时（Onebox 端点本就不返回会话），用它们逐个 getById。
 */
export const SEED_CONV_IDS = [
  '72273301682',
  '3249641022',
  '63473767346',
  '69712715263',
  '76289412921',
  '76081481934',
  '78016518647',
  '4615598166',
  '79553200501',
  '63760502903',
];
