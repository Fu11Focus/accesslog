import { IUser } from '#users/auth/domain';
import { IAuthService } from '#users/auth/domain/auth.service.interface';
import { PrismaService } from '#prisma/prisma.service';
import { EncryptionService } from '#shared/domain/services/encryption.service';
import { JwtService } from '@nestjs/jwt';
import { IJwtPayload } from '#users/auth/domain/interfaces/jwt-payload.interface';
import * as bcrypt from 'bcrypt';
import { ILoginResult, IRefreshTokenResult } from '#users/auth/domain/interfaces/auth.types';
import { AuthMapper } from './auth.mapper';
import { Injectable, NotFoundException, UnauthorizedException, ConflictException } from '@nestjs/common';
import { RefreshTokenService } from '#users/auth/domain/services/refresh-token.service';
import { EncryptionKeyCacheService } from '#users/auth/domain/services';

@Injectable()
export class AuthService implements IAuthService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly encryptionService: EncryptionService,
        private readonly jwtService: JwtService,
        private readonly authMapper: AuthMapper,
        private readonly refreshTokenService: RefreshTokenService,
        private readonly encryptionKeyCache: EncryptionKeyCacheService,
    ) { }

    async login(email: string, password: string): Promise<ILoginResult> {
        const user = await this.prisma.user.findUnique({ where: { email } });
        if (!user) {
            throw new NotFoundException('User not found');
        }

        const isPasswordValid = bcrypt.compareSync(password, user.passwordHash);
        if (!isPasswordValid) {
            throw new UnauthorizedException('Invalid password');
        }

        const encryptionKey = this.encryptionService.deriveKey(
            password,
            user.encryptionSalt,
        );
        const encryptionKeyBase64 = encryptionKey.toString('base64');
        await this.encryptionKeyCache.set(user.id, encryptionKeyBase64);

        const payload: IJwtPayload = {
            sub: user.id,
            email: user.email,
            encryptionKey: encryptionKey.toString('base64'),
        };

        const accessToken = await this.jwtService.signAsync(
            { ...payload },
            {
                secret: process.env.JWT_SECRET,
                expiresIn: '15m',
            },
        );

        const refreshToken = await this.refreshTokenService.generateRefreshToken(user.id);

        return {
            user: this.authMapper.toUserDomain(user),
            accessToken,
            refreshToken,
        };
    }

    async register(email: string, password: string): Promise<IUser> {
        const existingUser = await this.prisma.user.findUnique({ where: { email } });
        if (existingUser) {
            throw new ConflictException('User already exists');
        }

        const encryptionSalt = this.encryptionService.generateSalt();
        const passwordHash = bcrypt.hashSync(password, 10);

        const user = await this.prisma.user.create({
            data: { email, passwordHash, encryptionSalt },
        });

        return this.authMapper.toUserDomain(user);
    }

    async verifyPassword(userId: string, password: string): Promise<boolean> {
        const user = await this.prisma.user.findUnique({ where: { id: userId } });
        if (!user) return false;
        return bcrypt.compareSync(password, user.passwordHash);
    }

    async refresh(refreshToken: string, password?: string): Promise<IRefreshTokenResult> {
        const { userId, tokenId } = await this.refreshTokenService.verifyRefreshToken(refreshToken);

        const user = await this.prisma.user.findUnique({ where: { id: userId } });
        if (!user) {
            throw new NotFoundException('User not found');
        }
        await this.refreshTokenService.revokeRefreshToken(tokenId);

        const encryptionKey = await this.encryptionKeyCache.get(userId);
        const hasEncryptionKey = encryptionKey !== null;

        const payload: IJwtPayload = {
            sub: user.id,
            email: user.email,
            encryptionKey: '',
        };

        const accessToken = await this.jwtService.signAsync(
            { ...payload },
            {
                secret: process.env.JWT_SECRET,
                expiresIn: '15m',
            },
        );

        if (hasEncryptionKey) {
            await this.encryptionKeyCache.refresh(userId);
        }

        const newRefreshToken = await this.refreshTokenService.generateRefreshToken(user.id);

        return {
            accessToken,
            refreshToken: newRefreshToken,
        };
    }

    async logout(refreshToken: string): Promise<void> {
        try {
            const { tokenId } = await this.refreshTokenService.verifyRefreshToken(refreshToken);
            await this.refreshTokenService.revokeRefreshToken(tokenId);
        } catch {
        }
    }

    async logoutAll(userId: string): Promise<void> {
        await this.refreshTokenService.revokeAllUserTokens(userId);
        await this.encryptionKeyCache.delete(userId);
    }
}
