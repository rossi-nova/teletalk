/** 网关对外 DTO —— 与钉钉内部结构解耦 */

export interface Dialog {
  id: string;
  title: string;
  type: 'single' | 'group';
  avatarUrl?: string;
  unreadCount: number;
  lastMessage?: Message;
  updatedAt: number;
}

export interface Message {
  id: string;
  dialogId: string;
  senderId: string;
  senderName?: string;
  text: string;
  createdAt: number;
  kind: 'text' | 'image' | 'file' | 'system';
  resourceId?: string;
  self: boolean;
  /** 发送者稳定索引（钉钉历史接口不返回真实 uid，用此值区分发言人） */
  senderKey?: number;
}

export interface SendTextRequest {
  dialogId: string;
  text: string;
}

export interface AuthState {
  loggedIn: boolean;
  deviceId?: string;
  userId?: string;
  orgId?: string;
}

export type GatewayEvent =
  | { type: 'message'; message: Message }
  | { type: 'dialog'; dialog: Dialog }
  | { type: 'status'; auth: AuthState };
