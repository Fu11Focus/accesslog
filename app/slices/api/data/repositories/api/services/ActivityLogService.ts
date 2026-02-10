/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class ActivityLogService {
    /**
     * Get all activities for a specific access
     * @param accessId
     * @returns any
     * @throws ApiError
     */
    public static getActivitiesByAccessId(
        accessId: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/activity-log/access/{accessId}',
            path: {
                'accessId': accessId,
            },
        });
    }
    /**
     * Get all activities for a specific project
     * @param projectId
     * @returns any
     * @throws ApiError
     */
    public static getActivitiesByProjectId(
        projectId: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/activity-log/project/{projectId}',
            path: {
                'projectId': projectId,
            },
        });
    }
}
