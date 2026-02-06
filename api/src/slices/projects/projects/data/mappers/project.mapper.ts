import { Injectable } from "@nestjs/common";
import { Project } from "@prisma/client";
import { IProject } from "#projects/projects/domain/interfaces";
import { ProjectStatus } from "#projects/projects/domain/interfaces";

@Injectable()
export class ProjectMapper {
    toData(project: Project): IProject {
        return {
            id: project.id,
            name: project.name,
            clientName: project.clientName || undefined,
            status: ProjectStatus[project.status],
            description: project.description || undefined,
            createdAt: project.createdAt,
            updatedAt: project.updatedAt,
        };
    }
}