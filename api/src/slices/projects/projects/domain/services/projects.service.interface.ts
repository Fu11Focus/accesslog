import { IProject } from "../interfaces";
import { ICreateProject } from "../interfaces/createProject.interface";
import { IUpdateProject } from "../interfaces/updateProject.interface";

export abstract class IProjectsService {
    abstract createProject(userId: string, project: ICreateProject): Promise<IProject>;
    abstract updateProject(id: string, project: IUpdateProject, userId: string): Promise<IProject>;
    abstract deleteProject(id: string, userId: string): Promise<Boolean>;
    abstract getProject(id: string, userId: string): Promise<IProject>;
    abstract getAllProjects(userId: string): Promise<IProject[]>;
}