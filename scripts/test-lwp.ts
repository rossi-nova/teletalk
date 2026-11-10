/** 用真实凭据测试 LWP 连接与 /reg 注册 */
import { DingtalkSession } from '../apps/server/src/lwp/session.js';
import { loadConfig } from '../apps/server/src/config.js';

const cfg = loadConfig();
if (!cfg.dingtalk.deviceId || !cfg.dingtalk.token) {
  console.log('缺少 DT_DEVICE_ID / DT_TOKEN，跳过');
  process.exit(0);
}

const s = new DingtalkSession(cfg.dingtalk);
try {
  await s.connect();
  console.log('✓ TLS 连接建立');

  const look = await s.lookup();
  console.log('✓ Aladdin/lookup:', look.code, look.body.length, 'B');

  const init = await s.regInit();
  console.log('✓ reg/init:', init.code);

  const reg = await s.register();
  console.log('✓ /reg:', reg.code, reg.body.length, 'B');

  if (reg.code === 200) {
    s.subscribe();
    console.log('✓ 已订阅 /s/sync');
    await new Promise((r) => setTimeout(r, 3000));
  }
} catch (e) {
  console.error('✗', (e as Error).message);
} finally {
  s.close();
  process.exit(0);
}
