/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { DashboardResponseDto } from '../models/DashboardResponseDto';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class DashboardService {
    /**
     * Get dashboard data
     * @returns DashboardResponseDto
     * @throws ApiError
     */
    public static getDashboardData(): CancelablePromise<DashboardResponseDto> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/dashboard',
        });
    }
}
