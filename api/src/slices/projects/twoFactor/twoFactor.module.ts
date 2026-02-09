import { Module } from "@nestjs/common";
import { PrismaModule } from "#prisma/prisma.module";
import { TwoFactorService } from "./domain/services/twoFactor.service";
import { ITwoFactorGateway } from "./domain/gateways/twoFactor.gateway";
import { TwoFactorGateway } from "./data/gateways/twoFactor.gateway";
import { TwoFactorMapper } from "./data/twoFactor.mapper";
import { TwoFactorController } from "./twoFactor.controller";

@Module({
    imports: [PrismaModule],
    controllers: [TwoFactorController],
    providers: [
        { provide: ITwoFactorGateway, useClass: TwoFactorGateway },
        TwoFactorService,
        TwoFactorMapper,
    ],
    exports: [TwoFactorService],
})
export class TwoFactorModule { }
