import { Module } from "@nestjs/common";
import { AccessService } from "./data/access.service";
import { AccessMapper } from "./data/access.mapper";
import { AccessController } from "./controllers/access.controller";
import { EncryptionService } from "#shared/domain/services/encryption.service";
import { PrismaModule } from "#prisma/prisma.module";

@Module({
    imports: [PrismaModule],
    providers: [AccessService, AccessMapper, EncryptionService],
    exports: [AccessService],
    controllers: [AccessController]
})

export class AccessModule { }
