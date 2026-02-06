import { Injectable, NotFoundException } from "@nestjs/common";
import { IProjectsService } from "#projects/projects/domain/services";
import { IProject } from "#projects/projects/domain/interfaces";
import { PrismaService } from "#prisma/prisma.service";
import { ProjectMapper } from "../mappers/project.mapper";
import { ICreateProject } from "#projects/projects/domain/interfaces/createProject.interface";
import { IUpdateProject } from "#projects/projects/domain/interfaces/updateProject.interface";


@Injectable()
export class ProjectsService implements IProjectsService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly mapper: ProjectMapper,
    ) { }

    async createProject(userId: string, project: ICreateProject): Promise<IProject> {
        const createdProject = await this.prisma.project.create({
            data: {
                ...project,
                userId,
            },
        });

        return this.mapper.toData(createdProject);
    }

    async updateProject(project: IUpdateProject, userId: string): Promise<IProject> {
        const updatedProject = await this.prisma.project.update({
            where: {
                id: project.id,
                userId,
            },
            data: {
                ...project,
            },
        });

        return this.mapper.toData(updatedProject);
    }

    async deleteProject(id: string, userId: string): Promise<Boolean> {
        await this.prisma.project.delete({
            where: {
                id,
                userId,
            },
        });

        return true;
    }

    async getProject(id: string, userId: string): Promise<IProject> {
        const project = await this.prisma.project.findUnique({
            where: {
                id,
                userId,
            },
        });

        if (!project) {
            throw new NotFoundException("Project not found");
        }

        return this.mapper.toData(project);
    }

    async getAllProjects(userId: string): Promise<IProject[]> {
        const projects = await this.prisma.project.findMany({
            where: {
                userId,
            },
        });

        return projects.map((project) => this.mapper.toData(project));
    }
}