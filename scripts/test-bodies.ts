/** 用真实抓包验证请求体构造器 */
import { strId } from '../apps/server/src/lwp/bodies.js';

const cases = [
  { expect: 'ab3639373132373135323633', id: '69712715263' },
  { expect: 'aa33323439363431303232', id: '3249641022' },
];

let pass = 0;
for (const c of cases) {
  const mine = strId(c.id).toString('hex');
  const ok = mine === c.expect;
  console.log(`${ok ? '✓' : '✗'} ${c.id}  期望=${c.expect}  实得=${mine}`);
  if (ok) pass++;
}
console.log(`\n${pass}/${cases.length} 通过`);
process.exit(pass === cases.length ? 0 : 1);
