import { Body, Controller, Get, Post, Req, Res, Response, UnauthorizedException } from "@nestjs/common";
import { AuthService } from "#users/auth/data/auth.service";
import { ApiBearerAuth, ApiOkResponse, ApiOperation, ApiTags } from "@nestjs/swagger";
import { Public } from "#users/auth/decorators/public.decorator";
import {
    LoginResponseDto, AuthDto, RefreshTokenDto, RefreshResponseDto,
    MeResponseDto, MessageResponseDto, ChangePasswordDto,
    LoginVerifyTotpDto, VerifyTotpDto, DisableTwoFactorDto,
    TwoFactorSetupResponseDto, TwoFactorBackupCodesResponseDto,
    TwoFactorStatusResponseDto, LoginTwoFactorRequiredDto,
} from "#users/auth/dtos";
import { UserDto } from "#users/users/dtos/user.dto";
import * as express from "express";
import { User } from "#users/auth/decorators/user.decorator";
import type { IJwtPayload } from "#users/auth/domain";
import { TwoFactorAuthService } from "#users/auth/domain/services";

@ApiTags('auth')
@Controller('auth')
export class AuthController {
    constructor(
        private readonly authService: AuthService,
        private readonly twoFactorService: TwoFactorAuthService,
    ) { }


    private setRefreshTokenCookie(res: express.Response, token: string) {
        res.cookie('refreshToken', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
            path: '/auth', // Only for auth endpoints
        });
    }

    private clearRefreshTokenCookie(res: express.Response) {
        res.clearCookie('refreshToken', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            path: '/auth',
        });
    }

    @Public()
    @Post('login')
    @ApiOperation({
        description: 'Login user',
        operationId: 'login',
    })
    @ApiOkResponse({ type: LoginResponseDto })
    async login(@Body() data: AuthDto, @Response({ passthrough: true }) res: express.Response): Promise<LoginResponseDto | LoginTwoFactorRequiredDto> {
        const result = await this.authService.login(data.email, data.password);

        if ('requiresTwoFactor' in result) {
            return {
                requiresTwoFactor: true,
                sessionToken: result.sessionToken,
            };
        }

        this.setRefreshTokenCookie(res, result.refreshToken);

        return {
            ...result,
            tokenType: 'Bearer',
        };
    }

    @Public()
    @Post('register')
    @ApiOperation({
        description: 'Register user',
        operationId: 'register',
    })
    @ApiOkResponse({ type: UserDto })
    async register(@Body() data: AuthDto): Promise<UserDto> {
        return this.authService.register(data.email, data.password);
    }

    @Public()
    @Post('refresh')
    @ApiOperation({
        description: 'Refresh access token',
        operationId: 'refresh',
    })
    @ApiOkResponse({ type: RefreshResponseDto })
    async refresh(
        @Req() req: express.Request,
        @Body() dto: RefreshTokenDto,
        @Res({ passthrough: true }) res: express.Response,
    ): Promise<RefreshResponseDto> {
        const refreshToken = req.cookies?.refreshToken || dto.refreshToken;

        if (!refreshToken) {
            throw new UnauthorizedException('Refresh token not provided');
        }

        const result = await this.authService.refresh(refreshToken);

        this.setRefreshTokenCookie(res, result.refreshToken);

        return {
            accessToken: result.accessToken,
            refreshToken: result.refreshToken,
        };
    }

    @Post('logout')
    @ApiBearerAuth()
    @ApiOperation({ summary: 'Logout and revoke refresh token' })
    @ApiOkResponse({ type: MessageResponseDto })
    async logout(
        @Req() req: express.Request,
        @Res({ passthrough: true }) res: express.Response,
    ) {
        const refreshToken = req.cookies?.refreshToken;

        if (refreshToken) {
            await this.authService.logout(refreshToken);
        }

        this.clearRefreshTokenCookie(res);

        return { message: 'Logged out successfully' };
    }

    @Post('logout-all')
    @ApiBearerAuth()
    @ApiOperation({ summary: 'Logout from all devices' })
    @ApiOkResponse({ type: MessageResponseDto })
    async logoutAll(
        @User() user: IJwtPayload,
        @Res({ passthrough: true }) res: express.Response,
    ) {
        await this.authService.logoutAll(user.sub);
        this.clearRefreshTokenCookie(res);

        return { message: 'Logged out from all devices' };
    }

    @Post('change-password')
    @ApiBearerAuth()
    @ApiOperation({
        description: 'Change user password and re-encrypt all data',
        operationId: 'changePassword',
    })
    @ApiOkResponse({ type: LoginResponseDto })
    async changePassword(
        @User() user: IJwtPayload,
        @Body() dto: ChangePasswordDto,
        @Res({ passthrough: true }) res: express.Response,
    ): Promise<LoginResponseDto> {
        const result = await this.authService.changePassword(user.sub, dto.currentPassword, dto.newPassword);

        this.setRefreshTokenCookie(res, result.refreshToken);

        return {
            ...result,
            tokenType: 'Bearer',
        };
    }

    @Get('me')
    @ApiBearerAuth()
    @ApiOperation({ summary: 'Get current user' })
    @ApiOkResponse({ type: MeResponseDto })
    async me(@User() user: IJwtPayload): Promise<MeResponseDto> {
        const twoFactorEnabled = await this.twoFactorService.isEnabled(user.sub);
        return {
            id: user.sub,
            email: user.email,
            twoFactorEnabled,
        };
    }

    // --- Two-Factor Authentication ---

    @Public()
    @Post('2fa/verify-login')
    @ApiOperation({
        summary: 'Complete 2FA login',
        operationId: 'verifyTwoFactorLogin',
    })
    @ApiOkResponse({ type: LoginResponseDto })
    async verifyTwoFactorLogin(
        @Body() dto: LoginVerifyTotpDto,
        @Res({ passthrough: true }) res: express.Response,
    ): Promise<LoginResponseDto> {
        const result = await this.authService.completeTwoFactorLogin(dto.sessionToken, dto.code);

        this.setRefreshTokenCookie(res, result.refreshToken);

        return {
            ...result,
            tokenType: 'Bearer',
        };
    }

    @Post('2fa/setup')
    @ApiBearerAuth()
    @ApiOperation({
        summary: 'Generate 2FA setup (QR code + secret)',
        operationId: 'setupTwoFactor',
    })
    @ApiOkResponse({ type: TwoFactorSetupResponseDto })
    async setupTwoFactor(@User() user: IJwtPayload): Promise<TwoFactorSetupResponseDto> {
        return this.twoFactorService.generateSetup(user.sub, user.email, user.encryptionKey);
    }

    @Post('2fa/confirm')
    @ApiBearerAuth()
    @ApiOperation({
        summary: 'Confirm 2FA setup with first TOTP code',
        operationId: 'confirmTwoFactor',
    })
    @ApiOkResponse({ type: TwoFactorBackupCodesResponseDto })
    async confirmTwoFactor(
        @User() user: IJwtPayload,
        @Body() dto: VerifyTotpDto,
    ): Promise<TwoFactorBackupCodesResponseDto> {
        const backupCodes = await this.twoFactorService.confirmSetup(user.sub, dto.code, user.encryptionKey);
        return { backupCodes };
    }

    @Post('2fa/disable')
    @ApiBearerAuth()
    @ApiOperation({
        summary: 'Disable 2FA (requires password)',
        operationId: 'disableTwoFactor',
    })
    @ApiOkResponse({ type: MessageResponseDto })
    async disableTwoFactor(
        @User() user: IJwtPayload,
        @Body() dto: DisableTwoFactorDto,
    ): Promise<MessageResponseDto> {
        const isValid = await this.authService.verifyPassword(user.sub, dto.password);
        if (!isValid) {
            throw new UnauthorizedException('Invalid password');
        }
        await this.twoFactorService.disable(user.sub);
        return { message: '2FA has been disabled' };
    }

    @Get('2fa/status')
    @ApiBearerAuth()
    @ApiOperation({
        summary: 'Check if 2FA is enabled',
        operationId: 'getTwoFactorStatus',
    })
    @ApiOkResponse({ type: TwoFactorStatusResponseDto })
    async getTwoFactorStatus(@User() user: IJwtPayload): Promise<TwoFactorStatusResponseDto> {
        const enabled = await this.twoFactorService.isEnabled(user.sub);
        return { enabled };
    }

    @Post('2fa/backup-codes/regenerate')
    @ApiBearerAuth()
    @ApiOperation({
        summary: 'Regenerate backup codes (requires TOTP code)',
        operationId: 'regenerateBackupCodes',
    })
    @ApiOkResponse({ type: TwoFactorBackupCodesResponseDto })
    async regenerateBackupCodes(
        @User() user: IJwtPayload,
        @Body() dto: VerifyTotpDto,
    ): Promise<TwoFactorBackupCodesResponseDto> {
        const isValid = await this.twoFactorService.verifyTotp(user.sub, dto.code, user.encryptionKey);
        if (!isValid) {
            throw new UnauthorizedException('Invalid verification code');
        }
        const backupCodes = await this.twoFactorService.regenerateBackupCodes(user.sub, user.encryptionKey);
        return { backupCodes };
    }
}
