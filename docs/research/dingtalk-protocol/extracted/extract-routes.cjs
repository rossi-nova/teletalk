// 从 MainFrame.dll 提取 RPC 路由表，写入 routes.md
// 用法: node extract-routes.cjs [path/to/MainFrame.dll]
const fs = require('fs');
const path = require('path');
const target = process.argv[2] || 'C:/Program Files (x86)/DingDing/main/current/MainFrame.dll';
const s = fs.readFileSync(target).toString('latin1');
const re = /\/[rs]\/[A-Za-z][A-Za-z0-9_]*(\/[A-Za-z][A-Za-z0-9_]*){1,2}/g;
const set = new Set(); let m;
while ((m = re.exec(s)) !== null) { if (m[0].length <= 70) set.add(m[0]); }
const bySvc = {};
for (const k of set) {
  const p = k.split('/');
  const svc = k.startsWith('/s/') ? 's:' + p[2] : p[2];
  const meth = k.startsWith('/s/') ? (p[3] || '(push)') : p.slice(3).join('/');
  (bySvc[svc] ||= new Set()).add(meth);
}
const lines = ['# 钉钉客户端 RPC 路由表', '', '来源：`MainFrame.dll` 字符串段。', '',
  '`/r/` 为请求，「/s/」为订阅/推送。该文件由 `extract-routes.cjs` 生成。', '',
  `共 ${Object.keys(bySvc).length} 个服务、${set.size} 条路由。`, ''];
for (const svc of Object.keys(bySvc).sort()) {
  const ms = [...bySvc[svc]].sort();
  lines.push(`## ${svc} (${ms.length})`, '');
  for (const x of ms) lines.push(`- \`${x}\``);
  lines.push('');
}
fs.writeFileSync(path.join(__dirname, 'routes.md'), lines.join('\n'));
console.log('服务:', Object.keys(bySvc).length, '路由:', set.size);
