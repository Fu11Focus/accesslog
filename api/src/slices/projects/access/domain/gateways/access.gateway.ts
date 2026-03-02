export interface IAccessRecord {
    id: string;
    projectId: string;
    serviceName: string;
    serviceUrl: string;
    environment: string;
    accessLevel: string;
    login: string;
    passwordEncrypted: string;
    notes: string | null;
    owner: string | null;
    createdAt: Date;
    updatedAt: Date;
}

export abstract class IAccessGateway {
    abstract create(data: {
        projectId: string;
        serviceName?: string;
        serviceUrl?: string;
        environment: string;
        accessLevel?: string;
        login: string;
        passwordEncrypted: string;
        notes?: string;
        owner?: string;
    }): Promise<IAccessRecord>;
    abstract findById(id: string): Promise<IAccessRecord | null>;
    abstract findByProjectId(projectId: string, page: number, limit: number, filters?: { environment?: string; accessLevel?: string; sortBy?: string; sortOrder?: 'asc' | 'desc' }): Promise<{ data: IAccessRecord[]; total: number }>;
    abstract update(id: string, data: Partial<Omit<IAccessRecord, 'id' | 'createdAt' | 'updatedAt'>>): Promise<IAccessRecord>;
    abstract delete(id: string): Promise<void>;
    abstract projectExists(projectId: string): Promise<boolean>;
}
