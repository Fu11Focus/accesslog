import { Body, Controller, Delete, Get, Param, Post, Put, Query } from "@nestjs/common";
import { ProjectsService } from "../domain/services/projects.service";
import { ApiBearerAuth, ApiBody, ApiTags } from "@nestjs/swagger";
import { ApiOperation } from "@nestjs/swagger";
import { CreateProjectDto, UpdateProjectDto } from "../dtos";
import { IProject } from "../domain/interfaces";
import { User } from "#users/auth/decorators";
import { ProjectsQueryDto } from "../dtos/projects-query.dto";


@Controller('projects')
@ApiTags('Projects')
@ApiBearerAuth()
export class ProjectsController {
    constructor(
        private readonly service: ProjectsService,
    ) { }

    @Post()
    @ApiBody({ type: CreateProjectDto })
    @ApiOperation({
        description: 'Create a new project',
        operationId: 'createProject',
    })
    async createProject(@User() user, @Body() project: CreateProjectDto): Promise<IProject> {

        return this.service.createProject(user.id, project);
    }

    @Put(':id')
    @ApiBody({ type: UpdateProjectDto })
    @ApiOperation({
        description: 'Update a project',
        operationId: 'updateProject'
    })
    async updateProject(@Param('id') id: string, @Body() project: UpdateProjectDto, @User() user): Promise<IProject> {
        return this.service.updateProject(id, project, user.id);
    }


    @Get()
    @ApiOperation({
        description: 'Get all projects',
        operationId: 'getAllProjects',
    })
    async getAllProjects(@User() user, @Query() query: ProjectsQueryDto) {
        return this.service.getAllProjects(user.id, query.page, query.limit, {
            status: query.status,
            sortBy: query.sortBy,
            sortOrder: query.sortOrder,
        });
    }

    @Get(':id')
    @ApiOperation({
        description: 'Get a project by id',
        operationId: 'getProject',
    })
    async getProject(@User() user, @Param('id') id: string): Promise<IProject> {
        return this.service.getProject(id, user.id);
    }

    @Delete(':id')
    @ApiOperation({
        description: 'Delete a project by id',
        operationId: 'deleteProject',
    })
    async deleteProject(@User() user, @Param('id') id: string): Promise<Boolean> {
        return this.service.deleteProject(id, user.id);
    }
}

