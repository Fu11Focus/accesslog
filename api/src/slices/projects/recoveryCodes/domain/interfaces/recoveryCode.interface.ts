

export interface IRecoveryCode {
    id: string;
    twoFactorId: string;
    code?: string;
    used: boolean;
    usedAt?: Date;
    createdAt: Date;
    updatedAt: Date;
}