import { Injectable, NotFoundException } from "@nestjs/common";
import { IProjectsService } from "./projects.service.interface";
import { IProject } from "../interfaces";
import { ICreateProject } from "../interfaces/createProject.interface";
import { IUpdateProject } from "../interfaces/updateProject.interface";
import { IProjectsGateway } from "../gateways/projects.gateway";


@Injectable()
export class ProjectsService implements IProjectsService {
    constructor(
        private readonly gateway: IProjectsGateway,
    ) { }

    async createProject(userId: string, project: ICreateProject): Promise<IProject> {
        return this.gateway.create(userId, project);
    }

    async updateProject(id: string, project: IUpdateProject, userId: string): Promise<IProject> {
        return this.gateway.update(id, userId, project);
    }

    async deleteProject(id: string, userId: string): Promise<Boolean> {
        await this.gateway.delete(id, userId);
        return true;
    }

    async getProject(id: string, userId: string): Promise<IProject> {
        const project = await this.gateway.findById(id, userId);
        if (!project) {
            throw new NotFoundException("Project not found");
        }
        return project;
    }

    async getAllProjects(userId: string): Promise<IProject[]> {
        return this.gateway.findAllByUserId(userId);
    }
}
