/**
 * 用户资料响应解析
 *
 * 结构（实测）：
 *   <uid编码> <中文名> <拼音 a^b^c> <性别 M/F> <头像ID> <地区 中国_省_市> ...
 *
 * 昵称与 uid 的配对在同一个 body 内相邻出现，按「数字 → 中文」的邻近关系提取。
 */

export interface UserProfile {
  uid: string;
  nick: string;
  pinyin?: string;
  region?: string;
  avatarId?: string;
}

/** 从 getProfile 响应 body 中提取用户信息 */
export function parseProfiles(body: Buffer): UserProfile[] {
  const s = body.toString('utf8');
  const out: UserProfile[] = [];

  // 模式：昵称（中文 2-15 字）后紧跟拼音（小写字母 ^ 分隔）
  const re = /([一-龥][一-龥A-Za-z0-9()（）·]{1,14})\u0003?[^\u0000]{0,3}?([a-z]+(?:\^[a-z]+)+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(s))) {
    const nick = m[1]!;
    const pinyin = m[2]!;

    // uid：昵称前 60 字节内最接近的数字串
    const before = s.slice(Math.max(0, m.index - 60), m.index);
    const uidM = before.match(/(\d{6,20})(?![\s\S]*\d{6,20})/);
    if (!uidM) continue;

    // 地区：昵称后 200 字节内
    const after = s.slice(m.index, m.index + 200);
    const regionM = after.match(/中国[_省]*[一-龥_]{0,20}/);

    out.push({
      uid: uidM[1]!,
      nick,
      pinyin,
      region: regionM?.[0],
    });
  }

  // 去重
  const seen = new Set<string>();
  return out.filter((p) => {
    if (seen.has(p.uid)) return false;
    seen.add(p.uid);
    return true;
  });
}

/** 合并多份解析结果 */
export function mergeProfiles(profiles: UserProfile[]): Map<string, string> {
  const map = new Map<string, string>();
  for (const p of profiles) {
    if (!map.has(p.uid)) map.set(p.uid, p.nick);
  }
  return map;
}
