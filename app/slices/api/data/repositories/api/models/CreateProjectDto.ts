/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateProjectDto = {
    name: string;
    clientName?: string;
    status: CreateProjectDto.status;
    description?: string;
};
export namespace CreateProjectDto {
    export enum status {
        ACTIVE = 'ACTIVE',
        ARCHIVED = 'ARCHIVED',
    }
}

