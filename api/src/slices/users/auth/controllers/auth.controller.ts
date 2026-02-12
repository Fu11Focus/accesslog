import { Body, Controller, Get, Post, Req, Res, Response, UnauthorizedException, UseInterceptors } from "@nestjs/common";
import { AuthService } from "#users/auth/data/auth.service";
import { ApiBearerAuth, ApiOkResponse, ApiOperation, ApiTags } from "@nestjs/swagger";
import { Public } from "#users/auth/decorators/public.decorator";
import { LoginResponseDto, AuthDto, RefreshTokenDto, RefreshResponseDto, MeResponseDto, MessageResponseDto } from "#users/auth/dtos";
import { UserDto } from "#users/users/dtos/user.dto";
import * as express from "express";
import { User } from "#users/auth/decorators/user.decorator";
import type { IJwtPayload } from "#users/auth/domain";

@ApiTags('auth')
@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) { }


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
    async login(@Body() data: AuthDto, @Response({ passthrough: true }) res: express.Response): Promise<LoginResponseDto> {
        const result = await this.authService.login(data.email, data.password);

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

    @Get('me')
    @ApiBearerAuth()
    @ApiOperation({ summary: 'Get current user' })
    @ApiOkResponse({ type: MeResponseDto })
    async me(@User() user: IJwtPayload): Promise<MeResponseDto> {
        return {
            id: user.sub,
            email: user.email,
        };
    }
}
