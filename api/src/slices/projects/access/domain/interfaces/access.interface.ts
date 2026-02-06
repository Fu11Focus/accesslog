import { AccessEnvironment, AccessLevel } from '.'

export interface IAccess {
    id: string;
    projectId: string;
    serviceName?: string;
    serviceUrl?: string;
    environment: AccessEnvironment;
    accessLevel: AccessLevel;
    login: string;
    password?: string;
    notes?: string;
    owner?: string;
    createdAt: Date;
    updatedAt: Date;
}