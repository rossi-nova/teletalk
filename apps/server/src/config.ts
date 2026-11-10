/** 网关配置：从环境变量读取，缺省值取自抓包实测的客户端标识 */
export interface Config {
  port: number;
  dingtalk: {
    host: string;
    deviceId: string;
    appKey: string;
    appkey: string;
    ua: string;
    token?: string;
    orgId?: string;
  };
}

const DEFAULT_UA =
  'Win/10.0 (Windows NT;zh_CN) App/9.0.5-Release.261029005 ' +
  'AliApp(DingTalk/9.0.5-Release.261029005) com.dingtalk.win/1771550 ' +
  'Channel/201200 Architecture/x86_64 Gaea/4.3.14-dingtalk.atlas4-SNAPSHOT';

export function loadConfig(): Config {
  return {
    port: Number(process.env.PORT ?? 8787),
    dingtalk: {
      host: process.env.DT_HOST ?? 'tls-desktop.dingtalk.com',
      deviceId: process.env.DT_DEVICE_ID ?? '',
      appKey: process.env.DT_APP_KEY ?? '564ca050be89b14ee78d692f6ded748d',
      appkey: process.env.DT_APPKEY ?? '85A09F60A599F5E1867EAB915A8BB07G',
      ua: process.env.DT_UA ?? DEFAULT_UA,
      token: process.env.DT_TOKEN,
      orgId: process.env.DT_ORG_ID,
    },
  };
}

export function validateConfig(cfg: Config): string[] {
  const missing: string[] = [];
  if (!cfg.dingtalk.deviceId) missing.push('DT_DEVICE_ID');
  if (!cfg.dingtalk.token) missing.push('DT_TOKEN（需先从抓包或登录流程获取）');
  return missing;
}
