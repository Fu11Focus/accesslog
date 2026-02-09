import { PrismaService } from "#prisma/prisma.service";
import { Injectable } from "@nestjs/common";
import { IProjectsGateway } from "../../domain/gateways/projects.gateway";
import { IProject } from "../../domain/interfaces";
import { ICreateProject } from "../../domain/interfaces/createProject.interface";
import { IUpdateProject } from "../../domain/interfaces/updateProject.interface";
import { ProjectMapper } from "../mappers/project.mapper";

@Injectable()
export class ProjectsGateway implements IProjectsGateway {
    constructor(
        private readonly prisma: PrismaService,
        private readonly mapper: ProjectMapper,
    ) { }

    async create(userId: string, data: ICreateProject): Promise<IProject> {
        const result = await this.prisma.project.create({
            data: { ...data, userId },
        });
        return this.mapper.toData(result);
    }

    async findById(id: string, userId: string): Promise<IProject | null> {
        const result = await this.prisma.project.findUnique({
            where: { id, userId },
        });
        return result ? this.mapper.toData(result) : null;
    }

    async findAllByUserId(userId: string): Promise<IProject[]> {
        const results = await this.prisma.project.findMany({
            where: { userId },
        });
        return results.map((project) => this.mapper.toData(project));
    }

    async update(id: string, userId: string, data: IUpdateProject): Promise<IProject> {
        const result = await this.prisma.project.update({
            where: { id, userId },
            data,
        });
        return this.mapper.toData(result);
    }

    async delete(id: string, userId: string): Promise<void> {
        await this.prisma.project.delete({
            where: { id, userId },
        });
    }
}
