import { PrismaModule } from "#prisma/prisma.module";
import { Module } from "@nestjs/common";
import { ProjectsService } from "./data/services/projects.service";
import { ProjectMapper } from "./data/mappers/project.mapper";
import { PrismaService } from "#prisma/prisma.service";
import { ProjectsController } from "./controllers/projects.controller";

@Module({
    imports: [PrismaModule],
    providers: [ProjectsService, ProjectMapper, PrismaService],
    exports: [ProjectsService],
    controllers: [ProjectsController],
})
export class ProjectsModule { }