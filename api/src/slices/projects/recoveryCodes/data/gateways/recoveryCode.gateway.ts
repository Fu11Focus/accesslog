import { PrismaService } from "#prisma/prisma.service";
import { Injectable } from "@nestjs/common";
import { IRecoveryCodeGateway, IRecoveryCodeRecord } from "../../domain/gateways/recoveryCode.gateway";
import { RecoveryCodeMapper } from "../recoveryCode.mapper";

@Injectable()
export class RecoveryCodeGateway implements IRecoveryCodeGateway {
    constructor(
        private readonly prisma: PrismaService,
        private readonly mapper: RecoveryCodeMapper,
    ) { }

    async create(data: { twoFactorId: string; codeEncrypted: string }): Promise<IRecoveryCodeRecord> {
        const result = await this.prisma.recoveryCode.create({ data });
        return this.toRecord(result);
    }

    async findById(id: string): Promise<IRecoveryCodeRecord | null> {
        const result = await this.prisma.recoveryCode.findUnique({ where: { id } });
        return result ? this.toRecord(result) : null;
    }

    async findByTwoFactorId(twoFactorId: string): Promise<IRecoveryCodeRecord[]> {
        const results = await this.prisma.recoveryCode.findMany({ where: { twoFactorId } });
        return results.map((r) => this.toRecord(r));
    }

    async markAsUsed(id: string): Promise<IRecoveryCodeRecord> {
        const result = await this.prisma.recoveryCode.update({
            where: { id },
            data: { used: true, usedAt: new Date() },
        });
        return this.toRecord(result);
    }

    async delete(id: string): Promise<void> {
        await this.prisma.recoveryCode.delete({ where: { id } });
    }

    async findAccessIdByTwoFactorId(twoFactorId: string): Promise<string | null> {
        const twoFactor = await this.prisma.twoFactor.findUnique({ where: { id: twoFactorId } });
        return twoFactor?.accessId ?? null;
    }

    private toRecord(record: any): IRecoveryCodeRecord {
        return {
            id: record.id,
            twoFactorId: record.twoFactorId,
            codeEncrypted: record.codeEncrypted,
            used: record.used,
            usedAt: record.usedAt || undefined,
            createdAt: record.createdAt,
            updatedAt: record.updatedAt,
        };
    }
}
