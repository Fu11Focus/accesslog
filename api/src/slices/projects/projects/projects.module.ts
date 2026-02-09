import { Module } from "@nestjs/common";
import { PrismaModule } from "#prisma/prisma.module";
import { ProjectsService } from "./domain/services/projects.service";
import { IProjectsGateway } from "./domain/gateways/projects.gateway";
import { ProjectsGateway } from "./data/gateways/projects.gateway";
import { ProjectMapper } from "./data/mappers/project.mapper";
import { ProjectsController } from "./controllers/projects.controller";

@Module({
    imports: [PrismaModule],
    providers: [
        { provide: IProjectsGateway, useClass: ProjectsGateway },
        ProjectsService,
        ProjectMapper,
    ],
    exports: [ProjectsService],
    controllers: [ProjectsController],
})
export class ProjectsModule { }
