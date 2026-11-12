/** 验证：不带 x5-sign 时 /reg 与业务接口是否可用（结论：不需要） */
import { execFileSync, execSync } from 'node:child_process';
import { LwpClient } from '../apps/server/src/lwp/client.js';
import { MidGenerator } from '../apps/server/src/lwp/frame.js';
const EXE='C:/Users/xrl/Codes/teletalk/tools/sign/build/grab-all.exe';
const g=JSON.parse(execFileSync(EXE,{encoding:'utf8',stdio:['ignore','pipe','ignore']}).trim()) as any;
console.log('token:', g.token.slice(0,30)+'...', 'did:', g.did, 'x5:', g.x5sign ? '有' : '无');
// 关钉钉防互踢
try { execSync('taskkill /IM DingTalk.exe /F',{stdio:'ignore'}); await new Promise(r=>setTimeout(r,3000)); console.log('钉钉已关'); } catch {}
const mid=new MidGenerator();
const c=new LwpClient({host:'tls-desktop.dingtalk.com'});
await c.connect();
const base=()=>({mid:mid.next(),did:g.did,'app-key':'564ca050be89b14ee78d692f6ded748d',appkey:'85A09F60A599F5E1867EAB915A8BB07G',
  ua:'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AliApp(DingTalk/9.0.5) com.dingtalk.win/1771550 Channel/',token:g.token,dt:'p'});
const reg=await c.request('/reg',base());
console.log('[/reg 无x5]',reg.code,reg.headers['auth-route-logic-unit']??'');
await new Promise(r=>setTimeout(r,500));
// 业务接口不带 x5
const lm=await c.request('/r/IDLMessage/listMessagesPaginationV2',base(),
  Buffer.from('8601ab373232373333303136383202c203cf0000019f61fae90504c2051d06bc332d37323237333330313638322d3134323636393934303038383836','hex'));
console.log('[listMessagesV2 无x5]',lm.code,lm.body.length+'B');
const gb=await c.request('/r/IDLConversation/getById',base(),Buffer.from('aa33323439363431303232','hex'));
console.log('[getById 无x5]',gb.code,gb.body.length+'B');
c.close();
