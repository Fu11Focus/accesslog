import { Injectable } from "@nestjs/common";
import { TwoFactor } from "@prisma/client";
import { ITwoFactor, TwoFactorType } from "../domain/interfaces";

@Injectable()
export class TwoFactorMapper {
    toData(twoFactor: TwoFactor): ITwoFactor {
        return {
            id: twoFactor.id,
            accessId: twoFactor.accessId,
            type: twoFactor.type as unknown as TwoFactorType,
            enabled: twoFactor.enabled,
            createdAt: twoFactor.createdAt,
            updatedAt: twoFactor.updatedAt,
        };
    }
}