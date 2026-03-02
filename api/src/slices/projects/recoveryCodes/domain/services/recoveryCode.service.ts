import { ForbiddenException, Injectable, NotFoundException } from "@nestjs/common";
import { IRecoveryCode } from "../interfaces/recoveryCode.interface";
import { ICreateRecoveryCode } from "../interfaces/createRecoveryCode.interface";
import { IRecoveryCodeGateway, IRecoveryCodeRecord } from "../gateways/recoveryCode.gateway";
import { EncryptionService } from "#shared/domain/services/encryption.service";
import { IActivityLogGateway } from "#activityLog/domain/activityLog.gateway";
import { ActionType } from "#activityLog/domain/interfaces/activityLog.interface";


@Injectable()
export class RecoveryCodeService {
    constructor(
        private readonly gateway: IRecoveryCodeGateway,
        private readonly encryptionService: EncryptionService,
        private readonly activityLogGateway: IActivityLogGateway,
    ) { }

    async createRecoveryCode(data: ICreateRecoveryCode, encryptionKey: string, userId: string): Promise<IRecoveryCode> {
        const isOwner = await this.gateway.twoFactorBelongsToUser(data.twoFactorId, userId);
        if (!isOwner) {
            throw new ForbiddenException('Two-factor not found');
        }
        const codeEncrypted = this.encryptionService.encrypt(data.code, encryptionKey);
        const record = await this.gateway.create({
            twoFactorId: data.twoFactorId,
            codeEncrypted,
        });
        return { ...this.toData(record), code: data.code };
    }

    async getRecoveryCodeById(id: string, encryptionKey: string, userId: string): Promise<IRecoveryCode> {
        const isOwner = await this.gateway.belongsToUser(id, userId);
        if (!isOwner) {
            throw new ForbiddenException('Recovery code not found');
        }
        const record = await this.gateway.findById(id);
        if (!record) {
            throw new NotFoundException("Recovery code not found");
        }
        return {
            ...this.toData(record),
            code: this.encryptionService.decrypt(record.codeEncrypted, encryptionKey),
        };
    }

    async getRecoveryCodesByTwoFactorId(twoFactorId: string, encryptionKey: string, userId: string): Promise<IRecoveryCode[]> {
        const isOwner = await this.gateway.twoFactorBelongsToUser(twoFactorId, userId);
        if (!isOwner) {
            throw new ForbiddenException('Two-factor not found');
        }
        const records = await this.gateway.findByTwoFactorId(twoFactorId);
        return records.map((record) => ({
            ...this.toData(record),
            code: this.encryptionService.decrypt(record.codeEncrypted, encryptionKey),
        }));
    }

    async useRecoveryCode(id: string, encryptionKey: string, userId: string): Promise<IRecoveryCode> {
        const isOwner = await this.gateway.belongsToUser(id, userId);
        if (!isOwner) {
            throw new ForbiddenException('Recovery code not found');
        }
        const record = await this.gateway.markAsUsed(id);

        const accessId = await this.gateway.findAccessIdByTwoFactorId(record.twoFactorId);
        if (accessId) {
            await this.activityLogGateway.createActivityLog({
                accessId,
                userId,
                action: ActionType.recoveryCodeUsed,
            });
        }

        return {
            ...this.toData(record),
            code: this.encryptionService.decrypt(record.codeEncrypted, encryptionKey),
        };
    }

    async deleteRecoveryCode(id: string, userId: string): Promise<void> {
        const isOwner = await this.gateway.belongsToUser(id, userId);
        if (!isOwner) {
            throw new ForbiddenException('Recovery code not found');
        }
        await this.gateway.delete(id);
    }

    private toData(record: IRecoveryCodeRecord): IRecoveryCode {
        return {
            id: record.id,
            twoFactorId: record.twoFactorId,
            used: record.used,
            usedAt: record.usedAt,
            createdAt: record.createdAt,
            updatedAt: record.updatedAt,
        };
    }
}
