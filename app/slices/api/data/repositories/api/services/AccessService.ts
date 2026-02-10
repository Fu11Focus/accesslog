/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CreateAccessDto } from '../models/CreateAccessDto';
import type { UpdateAccessDto } from '../models/UpdateAccessDto';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class AccessService {
    /**
     * Create access
     * @param requestBody
     * @returns any
     * @throws ApiError
     */
    public static createAccess(
        requestBody: CreateAccessDto,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/access',
            body: requestBody,
            mediaType: 'application/json',
        });
    }
    /**
     * Update access by id
     * @param requestBody
     * @returns any
     * @throws ApiError
     */
    public static updateAccessById(
        requestBody: UpdateAccessDto,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/access',
            body: requestBody,
            mediaType: 'application/json',
        });
    }
    /**
     * Get access by project id
     * @param projectId
     * @returns any
     * @throws ApiError
     */
    public static getAccessByProjectId(
        projectId: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/access/projects/{projectId}',
            path: {
                'projectId': projectId,
            },
        });
    }
    /**
     * Get access by id
     * @param id
     * @returns any
     * @throws ApiError
     */
    public static getAccessById(
        id: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/access/{id}',
            path: {
                'id': id,
            },
        });
    }
    /**
     * Delete access by id
     * @param id
     * @returns any
     * @throws ApiError
     */
    public static deleteAccessById(
        id: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/access/{id}',
            path: {
                'id': id,
            },
        });
    }
}
