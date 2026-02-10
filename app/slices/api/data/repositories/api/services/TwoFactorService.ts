/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CreateTwoFactorDto } from '../models/CreateTwoFactorDto';
import type { UpdateTwoFactorDto } from '../models/UpdateTwoFactorDto';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class TwoFactorService {
    /**
     * @param requestBody
     * @returns any
     * @throws ApiError
     */
    public static twoFactorControllerCreateTwoFactor(
        requestBody: CreateTwoFactorDto,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/two-factor',
            body: requestBody,
            mediaType: 'application/json',
        });
    }
    /**
     * @param accessId
     * @returns any
     * @throws ApiError
     */
    public static twoFactorControllerGetTwoFactorByAccessId(
        accessId: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/two-factor/access/{accessId}',
            path: {
                'accessId': accessId,
            },
        });
    }
    /**
     * @param id
     * @returns any
     * @throws ApiError
     */
    public static twoFactorControllerGetTwoFactorById(
        id: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/two-factor/{id}',
            path: {
                'id': id,
            },
        });
    }
    /**
     * @param id
     * @param requestBody
     * @returns any
     * @throws ApiError
     */
    public static twoFactorControllerUpdateTwoFactor(
        id: string,
        requestBody: UpdateTwoFactorDto,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/two-factor/{id}',
            path: {
                'id': id,
            },
            body: requestBody,
            mediaType: 'application/json',
        });
    }
    /**
     * @param id
     * @returns any
     * @throws ApiError
     */
    public static twoFactorControllerDeleteTwoFactorById(
        id: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/two-factor/{id}',
            path: {
                'id': id,
            },
        });
    }
}
