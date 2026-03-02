import { IUser } from '#users/auth/domain';
import { IAuthService } from '#users/auth/domain/auth.service.interface';
import { PrismaService } from '#prisma/prisma.service';
import { EncryptionService } from '#shared/domain/services/encryption.service';
import { JwtService } from '@nestjs/jwt';
import { IJwtPayload } from '#users/auth/domain/interfaces/jwt-payload.interface';
import * as bcrypt from 'bcrypt';
import { ILoginResult, ITwoFactorLoginResult, IRefreshTokenResult } from '#users/auth/domain/interfaces/auth.types';
import { AuthMapper } from './auth.mapper';
import { Injectable, NotFoundException, UnauthorizedException, ConflictException } from '@nestjs/common';
import { RefreshTokenService } from '#users/auth/domain/services/refresh-token.service';
import { EncryptionKeyCacheService, TwoFactorAuthService } from '#users/auth/domain/services';

@Injectable()
export class AuthService implements IAuthService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly encryptionService: EncryptionService,
        private readonly jwtService: JwtService,
        private readonly authMapper: AuthMapper,
        private readonly refreshTokenService: RefreshTokenService,
        private readonly encryptionKeyCache: EncryptionKeyCacheService,
        private readonly twoFactorService: TwoFactorAuthService,
    ) { }

    async login(email: string, password: string): Promise<ILoginResult | ITwoFactorLoginResult> {
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

        if (user.twoFactorEnabled) {
            const sessionToken = await this.twoFactorService.createLoginSession(
                user.id,
                encryptionKeyBase64,
            );
            return { requiresTwoFactor: true, sessionToken };
        }

        await this.encryptionKeyCache.set(user.id, encryptionKeyBase64);

        const payload: IJwtPayload = {
            sub: user.id,
            email: user.email,
            encryptionKey: encryptionKeyBase64,
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

    async completeTwoFactorLogin(sessionToken: string, code: string): Promise<ILoginResult> {
        const session = await this.twoFactorService.getLoginSession(sessionToken);
        if (!session) {
            throw new UnauthorizedException('Session expired. Please log in again.');
        }

        const user = await this.prisma.user.findUnique({ where: { id: session.userId } });
        if (!user) {
            throw new NotFoundException('User not found');
        }

        const isValid = await this.twoFactorService.verifyTotp(
            user.id,
            code,
            session.encryptionKey,
        );
        if (!isValid) {
            throw new UnauthorizedException('Invalid verification code');
        }

        await this.twoFactorService.deleteLoginSession(sessionToken);
        await this.encryptionKeyCache.set(user.id, session.encryptionKey);

        const payload: IJwtPayload = {
            sub: user.id,
            email: user.email,
            encryptionKey: session.encryptionKey,
        };

        const accessToken = await this.jwtService.signAsync(
            { ...payload },
            { secret: process.env.JWT_SECRET, expiresIn: '15m' },
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
        if (!encryptionKey) {
            throw new UnauthorizedException('Session expired. Please log in again.');
        }

        const payload: IJwtPayload = {
            sub: user.id,
            email: user.email,
            encryptionKey,
        };

        const accessToken = await this.jwtService.signAsync(
            { ...payload },
            {
                secret: process.env.JWT_SECRET,
                expiresIn: '15m',
            },
        );

        await this.encryptionKeyCache.refresh(userId);

        const newRefreshToken = await this.refreshTokenService.generateRefreshToken(user.id);

        return {
            accessToken,
            refreshToken: newRefreshToken,
        };
    }

    async changePassword(userId: string, currentPassword: string, newPassword: string): Promise<ILoginResult> {
        const user = await this.prisma.user.findUnique({ where: { id: userId } });
        if (!user) {
            throw new NotFoundException('User not found');
        }

        const isPasswordValid = bcrypt.compareSync(currentPassword, user.passwordHash);
        if (!isPasswordValid) {
            throw new UnauthorizedException('Invalid current password');
        }

        const oldKeyBase64 = this.encryptionService.deriveKey(currentPassword, user.encryptionSalt).toString('base64');
        const newSalt = this.encryptionService.generateSalt();
        const newKey = this.encryptionService.deriveKey(newPassword, newSalt);
        const newKeyBase64 = newKey.toString('base64');
        const newPasswordHash = bcrypt.hashSync(newPassword, 10);

        const accesses = await this.prisma.access.findMany({
            where: { project: { userId } },
            select: { id: true, passwordEncrypted: true },
        });

        const recoveryCodes = await this.prisma.recoveryCode.findMany({
            where: { twoFactor: { access: { project: { userId } } } },
            select: { id: true, codeEncrypted: true },
        });

        await this.prisma.$transaction(async (tx) => {
            await tx.user.update({
                where: { id: userId },
                data: { passwordHash: newPasswordHash, encryptionSalt: newSalt },
            });

            for (const access of accesses) {
                const decrypted = this.encryptionService.decrypt(access.passwordEncrypted, oldKeyBase64);
                const reEncrypted = this.encryptionService.encrypt(decrypted, newKeyBase64);
                await tx.access.update({
                    where: { id: access.id },
                    data: { passwordEncrypted: reEncrypted },
                });
            }

            for (const code of recoveryCodes) {
                const decrypted = this.encryptionService.decrypt(code.codeEncrypted, oldKeyBase64);
                const reEncrypted = this.encryptionService.encrypt(decrypted, newKeyBase64);
                await tx.recoveryCode.update({
                    where: { id: code.id },
                    data: { codeEncrypted: reEncrypted },
                });
            }

            // Re-encrypt user 2FA fields
            if (user.twoFactorSecret) {
                const decryptedSecret = this.encryptionService.decrypt(user.twoFactorSecret, oldKeyBase64);
                const reEncryptedSecret = this.encryptionService.encrypt(decryptedSecret, newKeyBase64);
                const updateData: any = { twoFactorSecret: reEncryptedSecret };

                if (user.backupCodesEncrypted) {
                    const decryptedCodes = this.encryptionService.decrypt(user.backupCodesEncrypted, oldKeyBase64);
                    updateData.backupCodesEncrypted = this.encryptionService.encrypt(decryptedCodes, newKeyBase64);
                }

                await tx.user.update({
                    where: { id: userId },
                    data: updateData,
                });
            }
        });

        await this.encryptionKeyCache.set(userId, newKeyBase64);
        await this.refreshTokenService.revokeAllUserTokens(userId);

        const payload: IJwtPayload = {
            sub: user.id,
            email: user.email,
            encryptionKey: newKeyBase64,
        };

        const accessToken = await this.jwtService.signAsync(
            { ...payload },
            { secret: process.env.JWT_SECRET, expiresIn: '15m' },
        );

        const refreshToken = await this.refreshTokenService.generateRefreshToken(user.id);

        return {
            user: this.authMapper.toUserDomain(user),
            accessToken,
            refreshToken,
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
