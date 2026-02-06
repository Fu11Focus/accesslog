
export interface ICreateAccess {
    projectId: string;
    serviceName?: string;
    serviceUrl?: string;
    environment: AccessEnvironment;
    accessLevel: AccessLevel;
    login: string;
    password: string;
    notes?: string;
    owner?: string;
}

export enum AccessEnvironment {
    prod = 'PRODUCTION',
    stage = 'STAGING',
    dev = 'DEVELOPMENT'
}

export enum AccessLevel {
    admin = 'ADMIN',
    editor = 'EDITOR',
    viewer = 'VIEWER'
}