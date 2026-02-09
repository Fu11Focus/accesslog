import { Module } from "@nestjs/common";
import { PrismaModule } from "#prisma/prisma.module";
import { ActivityLogModule } from "#activityLog/activityLog.module";
import { RecoveryCodeService } from "./domain/services/recoveryCode.service";
import { IRecoveryCodeGateway } from "./domain/gateways/recoveryCode.gateway";
import { RecoveryCodeGateway } from "./data/gateways/recoveryCode.gateway";
import { RecoveryCodeMapper } from "./data/recoveryCode.mapper";
import { RecoveryCodeController } from "./controllers/recoveryCode.controller";
import { EncryptionService } from "#shared/domain/services/encryption.service";

@Module({
    imports: [PrismaModule, ActivityLogModule],
    providers: [
        { provide: IRecoveryCodeGateway, useClass: RecoveryCodeGateway },
        RecoveryCodeService,
        RecoveryCodeMapper,
        EncryptionService,
    ],
    controllers: [RecoveryCodeController],
    exports: [RecoveryCodeService],
})
export class RecoveryCodeModule { }
