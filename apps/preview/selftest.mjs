// 用 jsdom 之外的方式验证页面逻辑：直接 fetch 数据，跑一遍分组逻辑
const API = 'http://127.0.0.1:8787';
const dir = process.argv[2];
const r = await fetch(`${API}/api/replay?dir=${encodeURIComponent(dir)}`);
const data = await r.json();
if (data.error) { console.error('FAIL', data.error); process.exit(1); }
const byDialog = new Map();
for (const m of data.messages) {
  if (!byDialog.has(m.dialogId)) byDialog.set(m.dialogId, []);
  byDialog.get(m.dialogId).push(m);
}
console.log(`帧 ${data.frames}，消息 ${data.count}，会话 ${byDialog.size}`);
for (const [id, msgs] of byDialog) {
  console.log(`  ${id} -> ${msgs.map(m => m.text).join(' | ')}`);
}
