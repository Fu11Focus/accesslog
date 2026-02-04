import { Module } from "@nestjs/common";
import { AuthController } from "./controllers/auth.controller";
import { AuthService } from "./data/auth.service";
import { AuthMapper } from "./data/auth.mapper";
import { PrismaModule } from "#prisma/prisma.module";
import { JwtModule } from "@nestjs/jwt";
import { APP_GUARD } from '@nestjs/core';
import { AuthGuard } from "./guards/auth.guard";
import { EncryptionService } from "#shared/domain/services/encryption.service";
import { RefreshTokenService } from "./domain/services/refresh-token.service";
import { RedisModule } from "#shared/redis/redis.module";
import { EncryptionKeyCacheService } from "./domain/services";

@Module({
    imports: [
        PrismaModule,
        RedisModule,
        JwtModule.register({
            global: true,
            secret: process.env.JWT_SECRET,
            signOptions: { expiresIn: '15m' },
        }),
    ],
    controllers: [AuthController],
    providers: [
        AuthService,
        AuthMapper,
        RefreshTokenService,
        EncryptionKeyCacheService,
        EncryptionService,
        {
            provide: APP_GUARD,
            useClass: AuthGuard,
        },
    ],
    exports: [AuthService],
})

export class AuthModule { }
