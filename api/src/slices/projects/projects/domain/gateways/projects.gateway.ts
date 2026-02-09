import { IProject } from '../interfaces';
import { ICreateProject } from '../interfaces/createProject.interface';
import { IUpdateProject } from '../interfaces/updateProject.interface';

export abstract class IProjectsGateway {
    abstract create(userId: string, data: ICreateProject): Promise<IProject>;
    abstract findById(id: string, userId: string): Promise<IProject | null>;
    abstract findAllByUserId(userId: string): Promise<IProject[]>;
    abstract update(id: string, userId: string, data: IUpdateProject): Promise<IProject>;
    abstract delete(id: string, userId: string): Promise<void>;
}
