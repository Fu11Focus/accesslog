import { IProject } from "../interfaces";
import { ICreateProject } from "../interfaces/createProject.interface";
import { IUpdateProject } from "../interfaces/updateProject.interface";
import { IPaginatedResult } from "#shared/interfaces/paginated-result.interface";

export abstract class IProjectsService {
    abstract createProject(userId: string, project: ICreateProject): Promise<IProject>;
    abstract updateProject(id: string, project: IUpdateProject, userId: string): Promise<IProject>;
    abstract deleteProject(id: string, userId: string): Promise<Boolean>;
    abstract getProject(id: string, userId: string): Promise<IProject>;
    abstract getAllProjects(userId: string, page: number, limit: number, filters?: { status?: string; sortBy?: string; sortOrder?: 'asc' | 'desc' }): Promise<IPaginatedResult<IProject>>;
}