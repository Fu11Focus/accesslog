import { ProjectStatus } from "./project.interface";

export interface ICreateProject {
    name: string;
    clientName?: string;
    status: ProjectStatus;
    description?: string;
}