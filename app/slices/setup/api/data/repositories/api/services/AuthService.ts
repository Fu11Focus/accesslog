/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AuthDto } from '../models/AuthDto';
import type { LoginResponseDto } from '../models/LoginResponseDto';
import type { MeResponseDto } from '../models/MeResponseDto';
import type { MessageResponseDto } from '../models/MessageResponseDto';
import type { RefreshResponseDto } from '../models/RefreshResponseDto';
import type { RefreshTokenDto } from '../models/RefreshTokenDto';
import type { UserDto } from '../models/UserDto';
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
}
