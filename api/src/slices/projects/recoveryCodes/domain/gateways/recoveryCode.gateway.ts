export interface IRecoveryCodeRecord {
    id: string;
    twoFactorId: string;
    codeEncrypted: string;
    used: boolean;
    usedAt?: Date;
    createdAt: Date;
    updatedAt: Date;
}

export abstract class IRecoveryCodeGateway {
    abstract create(data: { twoFactorId: string; codeEncrypted: string }): Promise<IRecoveryCodeRecord>;
    abstract findById(id: string): Promise<IRecoveryCodeRecord | null>;
    abstract findByTwoFactorId(twoFactorId: string): Promise<IRecoveryCodeRecord[]>;
    abstract markAsUsed(id: string): Promise<IRecoveryCodeRecord>;
    abstract delete(id: string): Promise<void>;
    abstract findAccessIdByTwoFactorId(twoFactorId: string): Promise<string | null>;
}
