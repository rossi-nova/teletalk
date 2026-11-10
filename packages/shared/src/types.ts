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
