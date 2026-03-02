/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AuthDto } from '../models/AuthDto';
import type { ChangePasswordDto } from '../models/ChangePasswordDto';
import type { DisableTwoFactorDto } from '../models/DisableTwoFactorDto';
import type { LoginResponseDto } from '../models/LoginResponseDto';
import type { LoginVerifyTotpDto } from '../models/LoginVerifyTotpDto';
import type { MeResponseDto } from '../models/MeResponseDto';
import type { MessageResponseDto } from '../models/MessageResponseDto';
import type { RefreshResponseDto } from '../models/RefreshResponseDto';
import type { RefreshTokenDto } from '../models/RefreshTokenDto';
import type { TwoFactorBackupCodesResponseDto } from '../models/TwoFactorBackupCodesResponseDto';
import type { TwoFactorSetupResponseDto } from '../models/TwoFactorSetupResponseDto';
import type { TwoFactorStatusResponseDto } from '../models/TwoFactorStatusResponseDto';
import type { UserDto } from '../models/UserDto';
import type { VerifyTotpDto } from '../models/VerifyTotpDto';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class AuthService {
    /**
     * Login user
     * @param requestBody
     * @returns LoginResponseDto
     * @throws ApiError
     */
    public static login(
        requestBody: AuthDto,
    ): CancelablePromise<LoginResponseDto> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/auth/login',
            body: requestBody,
            mediaType: 'application/json',
        });
    }
    /**
     * Register user
     * @param requestBody
     * @returns UserDto
     * @throws ApiError
     */
    public static register(
        requestBody: AuthDto,
    ): CancelablePromise<UserDto> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/auth/register',
            body: requestBody,
            mediaType: 'application/json',
        });
    }
    /**
     * Refresh access token
     * @param requestBody
     * @returns RefreshResponseDto
     * @throws ApiError
     */
    public static refresh(
        requestBody: RefreshTokenDto,
    ): CancelablePromise<RefreshResponseDto> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/auth/refresh',
            body: requestBody,
            mediaType: 'application/json',
        });
    }
    /**
     * Logout and revoke refresh token
     * @returns MessageResponseDto
     * @throws ApiError
     */
    public static authControllerLogout(): CancelablePromise<MessageResponseDto> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/auth/logout',
        });
    }
    /**
     * Logout from all devices
     * @returns MessageResponseDto
     * @throws ApiError
     */
    public static authControllerLogoutAll(): CancelablePromise<MessageResponseDto> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/auth/logout-all',
        });
    }
    /**
     * Change user password and re-encrypt all data
     * @param requestBody
     * @returns LoginResponseDto
     * @throws ApiError
     */
    public static changePassword(
        requestBody: ChangePasswordDto,
    ): CancelablePromise<LoginResponseDto> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/auth/change-password',
            body: requestBody,
            mediaType: 'application/json',
        });
    }
    /**
     * Get current user
     * @returns MeResponseDto
     * @throws ApiError
     */
    public static authControllerMe(): CancelablePromise<MeResponseDto> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/auth/me',
        });
    }
    /**
     * Complete 2FA login
     * @param requestBody
     * @returns LoginResponseDto
     * @throws ApiError
     */
    public static verifyTwoFactorLogin(
        requestBody: LoginVerifyTotpDto,
    ): CancelablePromise<LoginResponseDto> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/auth/2fa/verify-login',
            body: requestBody,
            mediaType: 'application/json',
        });
    }
    /**
     * Generate 2FA setup (QR code + secret)
     * @returns TwoFactorSetupResponseDto
     * @throws ApiError
     */
    public static setupTwoFactor(): CancelablePromise<TwoFactorSetupResponseDto> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/auth/2fa/setup',
        });
    }
    /**
     * Confirm 2FA setup with first TOTP code
     * @param requestBody
     * @returns TwoFactorBackupCodesResponseDto
     * @throws ApiError
     */
    public static confirmTwoFactor(
        requestBody: VerifyTotpDto,
    ): CancelablePromise<TwoFactorBackupCodesResponseDto> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/auth/2fa/confirm',
            body: requestBody,
            mediaType: 'application/json',
        });
    }
    /**
     * Disable 2FA (requires password)
     * @param requestBody
     * @returns MessageResponseDto
     * @throws ApiError
     */
    public static disableTwoFactor(
        requestBody: DisableTwoFactorDto,
    ): CancelablePromise<MessageResponseDto> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/auth/2fa/disable',
            body: requestBody,
            mediaType: 'application/json',
        });
    }
    /**
     * Check if 2FA is enabled
     * @returns TwoFactorStatusResponseDto
     * @throws ApiError
     */
    public static getTwoFactorStatus(): CancelablePromise<TwoFactorStatusResponseDto> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/auth/2fa/status',
        });
    }
    /**
     * Regenerate backup codes (requires TOTP code)
     * @param requestBody
     * @returns TwoFactorBackupCodesResponseDto
     * @throws ApiError
     */
    public static regenerateBackupCodes(
        requestBody: VerifyTotpDto,
    ): CancelablePromise<TwoFactorBackupCodesResponseDto> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/auth/2fa/backup-codes/regenerate',
            body: requestBody,
            mediaType: 'application/json',
        });
    }
}
