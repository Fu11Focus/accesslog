/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CreateProjectDto } from '../models/CreateProjectDto';
import type { UpdateProjectDto } from '../models/UpdateProjectDto';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class ProjectsService {
    /**
     * Create a new project
     * @param requestBody
     * @returns any
     * @throws ApiError
     */
    public static createProject(
        requestBody: CreateProjectDto,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/projects',
            body: requestBody,
            mediaType: 'application/json',
        });
    }
    /**
     * Get all projects
     * @param page
     * @param limit
     * @param sortBy
     * @param sortOrder
     * @param status
     * @returns any
     * @throws ApiError
     */
    public static getAllProjects(
        page: number = 1,
        limit: number = 10,
        sortBy?: string,
        sortOrder?: 'asc' | 'desc',
        status?: 'ACTIVE' | 'ARCHIVED',
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/projects',
            query: {
                'page': page,
                'limit': limit,
                'sortBy': sortBy,
                'sortOrder': sortOrder,
                'status': status,
            },
        });
    }
    /**
     * Update a project
     * @param id
     * @param requestBody
     * @returns any
     * @throws ApiError
     */
    public static updateProject(
        id: string,
        requestBody: UpdateProjectDto,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/projects/{id}',
            path: {
                'id': id,
            },
            body: requestBody,
            mediaType: 'application/json',
        });
    }
    /**
     * Get a project by id
     * @param id
     * @returns any
     * @throws ApiError
     */
    public static getProject(
        id: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/projects/{id}',
            path: {
                'id': id,
            },
        });
    }
    /**
     * Delete a project by id
     * @param id
     * @returns any
     * @throws ApiError
     */
    public static deleteProject(
        id: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/projects/{id}',
            path: {
                'id': id,
            },
        });
    }
}
