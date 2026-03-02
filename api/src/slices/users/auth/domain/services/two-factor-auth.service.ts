import { Injectable, Inject, BadRequestException } from '@nestjs/common';
import { CACHE_MANAGER, Cache } from '@nestjs/cache-manager';
import { PrismaService } from '#prisma/prisma.service';
import { EncryptionService } from '#shared/domain/services/encryption.service';
import { generateSecret, generateURI, verifySync } from 'otplib';
import * as QRCode from 'qrcode';
import * as crypto from 'crypto';

interface BackupCode {
    code: string;
    used: boolean;
}

@Injectable()
export class TwoFactorAuthService {
    private readonly SESSION_PREFIX = '2fa-session:';
    private readonly SESSION_TTL = 300; // 5 minutes

    constructor(
        private readonly prisma: PrismaService,
        private readonly encryptionService: EncryptionService,
        @Inject(CACHE_MANAGER) private cacheManager: Cache,
    ) { }

    async generateSetup(userId: string, email: string, encryptionKey: string): Promise<{
        qrCodeDataUrl: string;
        secret: string;
        otpauthUrl: string;
    }> {
        const secret = generateSecret();
        const otpauthUrl = generateURI({ issuer: 'AccessLog', label: email, secret });
        const qrCodeDataUrl = await QRCode.toDataURL(otpauthUrl);

        const encryptedSecret = this.encryptionService.encrypt(secret, encryptionKey);

        await this.prisma.user.update({
            where: { id: userId },
            data: { twoFactorSecret: encryptedSecret, twoFactorEnabled: false },
        });

        return { qrCodeDataUrl, secret, otpauthUrl };
    }

    async confirmSetup(userId: string, code: string, encryptionKey: string): Promise<string[]> {
        const user = await this.prisma.user.findUnique({ where: { id: userId } });
        if (!user?.twoFactorSecret) {
            throw new BadRequestException('2FA setup not started');
        }
        if (user.twoFactorEnabled) {
            throw new BadRequestException('2FA is already enabled');
        }

        const secret = this.encryptionService.decrypt(user.twoFactorSecret, encryptionKey);
        const { valid: isValid } = verifySync({ token: code, secret });
        if (!isValid) {
            throw new BadRequestException('Invalid verification code');
        }

        const backupCodes = this.generateBackupCodes();
        const backupCodesData: BackupCode[] = backupCodes.map(c => ({ code: c, used: false }));
        const encryptedBackupCodes = this.encryptionService.encrypt(
            JSON.stringify(backupCodesData),
            encryptionKey,
        );

        await this.prisma.user.update({
            where: { id: userId },
            data: {
                twoFactorEnabled: true,
                backupCodesEncrypted: encryptedBackupCodes,
            },
        });

        return backupCodes;
    }

    async verifyTotp(userId: string, code: string, encryptionKey: string): Promise<boolean> {
        const user = await this.prisma.user.findUnique({ where: { id: userId } });
        if (!user?.twoFactorSecret || !user.twoFactorEnabled) {
            return false;
        }

        const secret = this.encryptionService.decrypt(user.twoFactorSecret, encryptionKey);

        // Try TOTP first
        const { valid } = verifySync({ token: code, secret });
        if (valid) {
            return true;
        }

        // Try backup code
        return this.useBackupCode(userId, code, encryptionKey);
    }

    async disable(userId: string): Promise<void> {
        await this.prisma.user.update({
            where: { id: userId },
            data: {
                twoFactorEnabled: false,
                twoFactorSecret: null,
                backupCodesEncrypted: null,
            },
        });
    }

    async isEnabled(userId: string): Promise<boolean> {
        const user = await this.prisma.user.findUnique({
            where: { id: userId },
            select: { twoFactorEnabled: true },
        });
        return user?.twoFactorEnabled ?? false;
    }

    async regenerateBackupCodes(userId: string, encryptionKey: string): Promise<string[]> {
        const backupCodes = this.generateBackupCodes();
        const backupCodesData: BackupCode[] = backupCodes.map(c => ({ code: c, used: false }));
        const encryptedBackupCodes = this.encryptionService.encrypt(
            JSON.stringify(backupCodesData),
            encryptionKey,
        );

        await this.prisma.user.update({
            where: { id: userId },
            data: { backupCodesEncrypted: encryptedBackupCodes },
        });

        return backupCodes;
    }

    // --- Login session management ---

    async createLoginSession(userId: string, encryptionKey: string): Promise<string> {
        const sessionToken = crypto.randomUUID();
        const key = this.SESSION_PREFIX + sessionToken;
        await this.cacheManager.set(key, JSON.stringify({ userId, encryptionKey }), this.SESSION_TTL);
        return sessionToken;
    }

    async getLoginSession(sessionToken: string): Promise<{ userId: string; encryptionKey: string } | null> {
        const key = this.SESSION_PREFIX + sessionToken;
        const value = await this.cacheManager.get<string>(key);
        if (!value) return null;
        return JSON.parse(value);
    }

    async deleteLoginSession(sessionToken: string): Promise<void> {
        const key = this.SESSION_PREFIX + sessionToken;
        await this.cacheManager.del(key);
    }

    // --- Private helpers ---

    private generateBackupCodes(count = 10): string[] {
        const codes: string[] = [];
        for (let i = 0; i < count; i++) {
            codes.push(crypto.randomBytes(4).toString('hex')); // 8-char hex
        }
        return codes;
    }

    private async useBackupCode(userId: string, code: string, encryptionKey: string): Promise<boolean> {
        const user = await this.prisma.user.findUnique({ where: { id: userId } });
        if (!user?.backupCodesEncrypted) return false;

        const decrypted = this.encryptionService.decrypt(user.backupCodesEncrypted, encryptionKey);
        const codes: BackupCode[] = JSON.parse(decrypted);

        const matchIndex = codes.findIndex(c => !c.used && c.code === code);
        if (matchIndex === -1) return false;

        codes[matchIndex].used = true;
        const reEncrypted = this.encryptionService.encrypt(JSON.stringify(codes), encryptionKey);

        await this.prisma.user.update({
            where: { id: userId },
            data: { backupCodesEncrypted: reEncrypted },
        });

        return true;
    }
}
