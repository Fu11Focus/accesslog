export interface IProject {
    id: string;
    name: string;
    clientName?: string;
    status: ProjectStatus;
    description?: string;
    createdAt: Date;
    updatedAt: Date;
}

export enum ProjectStatus {
    ACTIVE = 'ACTIVE',
    ARCHIVED = 'ARCHIVED'
}