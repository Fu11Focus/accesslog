import { Module } from "@nestjs/common";
import { PrismaModule } from "#prisma/prisma.module";
import { ActivityLogModule } from "#activityLog/activityLog.module";
import { AccessService } from "./domain/services/access.service";
import { IAccessGateway } from "./domain/gateways/access.gateway";
import { AccessGateway } from "./data/gateways/access.gateway";
import { AccessController } from "./controllers/access.controller";
import { EncryptionService } from "#shared/domain/services/encryption.service";

@Module({
    imports: [PrismaModule, ActivityLogModule],
    providers: [
        { provide: IAccessGateway, useClass: AccessGateway },
        AccessService,
        EncryptionService,
    ],
    exports: [AccessService],
    controllers: [AccessController],
})
export class AccessModule { }
