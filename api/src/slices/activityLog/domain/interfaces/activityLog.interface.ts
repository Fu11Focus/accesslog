


export interface IActivityLog {
    id: string;
    accessId: string;
    userId: string;
    action: ActionType;
    createdAt: Date;
    updatedAt: Date;
}

export enum ActionType {
    accessCreated = 'ACCESS_CREATED',
    accessUpdated = 'ACCESS_UPDATED',
    accessViewed = 'ACCESS_VIEWED',
    accessCopied = 'ACCESS_COPIED',
    accessDeleted = 'ACCESS_DELETED',
    passwordChanged = 'PASSWORD_CHANGED',
    recoveryCodeUsed = 'RECOVERY_CODE_USED',
    recoveryCodeViewed = 'RECOVERY_CODE_VIEWED',
}