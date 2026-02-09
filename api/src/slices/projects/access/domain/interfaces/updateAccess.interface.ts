import { AccessEnvironment, AccessLevel } from ".";


export interface IUpdateAccess {
    id: string;
    serviceName?: string;
    serviceUrl?: string;
    environment: AccessEnvironment;
    accessLevel: AccessLevel;
    login: string;
    password: string;
    notes?: string;
    owner?: string;
}