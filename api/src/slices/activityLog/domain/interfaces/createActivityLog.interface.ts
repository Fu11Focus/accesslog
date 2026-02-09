import { ActionType } from "./activityLog.interface";

export interface ICreateActivityLog {
    accessId: string;
    userId: string;
    action: ActionType;
} 