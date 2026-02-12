/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CreateRecoveryCodeDto } from '../models/CreateRecoveryCodeDto';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class RecoveryCodeService {
    /**
     * Create a recovery code
     * @param requestBody
     * @returns any
     * @throws ApiError
     */
    public static createRecoveryCode(
        requestBody: CreateRecoveryCodeDto,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/recovery-code',
            body: requestBody,
            mediaType: 'application/json',
        });
    }
    /**
     * Get recovery codes by two factor id
     * @param twoFactorId
     * @returns any
     * @throws ApiError
     */
    public static getRecoveryCodeByTwoFactorId(
        twoFactorId: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/recovery-code/two-factor/{twoFactorId}',
            path: {
                'twoFactorId': twoFactorId,
            },
        });
    }
    /**
     * Get a recovery code by id
     * @param id
     * @returns any
     * @throws ApiError
     */
    public static getRecoveryCodeById(
        id: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/recovery-code/{id}',
            path: {
                'id': id,
            },
        });
    }
    /**
     * Delete a recovery code
     * @param id
     * @returns any
     * @throws ApiError
     */
    public static deleteRecoveryCode(
        id: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/recovery-code/{id}',
            path: {
                'id': id,
            },
        });
    }
    /**
     * Use a recovery code
     * @param id
     * @returns any
     * @throws ApiError
     */
    public static useRecoveryCode(
        id: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'PATCH',
            url: '/recovery-code/{id}/use',
            path: {
                'id': id,
            },
        });
    }
}
