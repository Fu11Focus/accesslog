import { Injectable } from "@nestjs/common";
import { RecoveryCode } from "@prisma/client";
import { IRecoveryCode } from "../domain/interfaces/recoveryCode.interface";


@Injectable()
export class RecoveryCodeMapper {
    toData(recoveryCode: RecoveryCode): IRecoveryCode {
        return {
            id: recoveryCode.id,
            twoFactorId: recoveryCode.twoFactorId,
            used: recoveryCode.used,
            usedAt: recoveryCode.usedAt || undefined,
            createdAt: recoveryCode.createdAt,
            updatedAt: recoveryCode.updatedAt,
        };
    }
}