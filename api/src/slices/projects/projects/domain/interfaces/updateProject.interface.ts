import { ProjectStatus } from "#projects/projects/domain/interfaces";

export interface IUpdateProject {
    name?: string;
    clientName?: string;
    status?: ProjectStatus;
    description?: string;
}