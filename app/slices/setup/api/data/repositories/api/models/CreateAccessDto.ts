/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AccessEnvironment } from './AccessEnvironment';
import type { AccessLevel } from './AccessLevel';
export type CreateAccessDto = {
    projectId: string;
    serviceName: string;
    serviceUrl: string;
    environment: AccessEnvironment;
    accessLevel: AccessLevel;
    login: string;
    password: string;
    notes: string;
    owner: string;
};

