import { JwtService } from "@nestjs/jwt";
import { IRefreshTokenPayload } from "../interfaces/refresh-token-payload.interface";
import { Injectable, UnauthorizedException } from "@nestjs/common";
import * as crypto from 'crypto';
import { PrismaService } from "#prisma/prisma.service";

@Injectable()
export class RefreshTokenService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly jwtService: JwtService
    ) { }

    async generateRefreshToken(userId: string): Promise<string> {
        await this.prisma.refreshToken.deleteMany({
            where: {
                userId,
                expiresAt: {
                    lte: new Date()
                }
            }
        });

        const tokenValue = crypto.randomBytes(64).toString('hex');

        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 7);

        const refreshToken = await this.prisma.refreshToken.create({
            data: {
                userId,
                token: tokenValue,
                expiresAt,
            },
        });

        const payload: IRefreshTokenPayload = {
            sub: userId,
            tokenId: refreshToken.id,
        };

        return this.jwtService.signAsync(payload, {
            secret: process.env.REFRESH_TOKEN_SECRET,
            expiresIn: '7d',
        });
    }

    async verifyRefreshToken(token: string): Promise<{ userId: string; tokenId: string }> {
        try {
            const payload = await this.jwtService.verifyAsync<IRefreshTokenPayload>(token, {
                secret: process.env.REFRESH_TOKEN_SECRET,
            });

            const refreshToken = await this.prisma.refreshToken.findUnique({
                where: { id: payload.tokenId },
            });

            if (!refreshToken) {
                throw new UnauthorizedException('Refresh token not found');
            }

            if (refreshToken.expiresAt < new Date()) {
                await this.prisma.refreshToken.delete({ where: { id: payload.tokenId } });
                throw new UnauthorizedException('Refresh token expired');
            }

            if (refreshToken.userId !== payload.sub) {
                throw new UnauthorizedException('Token user mismatch');
            }

            return { userId: payload.sub, tokenId: payload.tokenId };
        } catch (error) {
            if (error instanceof UnauthorizedException) throw error;
            throw new UnauthorizedException('Invalid refresh token');
        }
    }

    async revokeRefreshToken(tokenId: string): Promise<void> {
        await this.prisma.refreshToken.delete({
            where: { id: tokenId },
        }).catch(() => { });
    }

    async revokeAllUserTokens(userId: string): Promise<void> {
        await this.prisma.refreshToken.deleteMany({
            where: { userId },
        });
    }
}