import { ApiBearerAuth, ApiOperation, ApiTags } from "@nestjs/swagger";
import { AccessService } from "../domain/services/access.service";
import { Body, Controller, Delete, Get, Param, Post, Put, UseGuards } from "@nestjs/common";
import { AuthGuard } from "#users/auth/guards";
import { User } from "#users/auth/decorators";
import { CreateAccessDto, UpdateAccessDto } from "../dtos";
import { IAccess } from "../domain/interfaces";

@ApiBearerAuth()
@UseGuards(AuthGuard)
@Controller('access')
@ApiTags('Access')
export class AccessController {
    constructor(private readonly accessService: AccessService) { }

    @Post()
    @ApiOperation({
        description: 'Create access',
        operationId: 'createAccess',
    })
    async createAccess(@User() user, @Body() data: CreateAccessDto): Promise<IAccess> {
        return this.accessService.createAccess(data, user.encryptionKey, user.id);
    }

    @Get('projects/:projectId')
    @ApiOperation({
        description: 'Get access by project id',
        operationId: 'getAccessByProjectId'
    })
    async getAccessByProjectId(@User() user, @Param('projectId') projectId: string) {
        return this.accessService.getAccessByProjectId(projectId, user.encryptionKey);
    }

    @Get(':id')
    @ApiOperation({
        description: 'Get access by id',
        operationId: 'getAccessById'
    })
    async getAccessById(@User() user, @Param('id') id: string) {
        return this.accessService.getAccessById(id, user.encryptionKey);
    }

    @Put()
    @ApiOperation({
        description: 'Update access by id',
        operationId: 'updateAccessById'
    })
    async updateAccessById(@User() user, @Body() data: UpdateAccessDto) {
        return this.accessService.updateAccess(data, user.encryptionKey, user.id);
    }

    @Delete(':id')
    @ApiOperation({
        description: 'Delete access by id',
        operationId: 'deleteAccessById'
    })
    async deleteAccessById(@User() user, @Param('id') id: string) {
        return this.accessService.deleteAccessById(id, user.id);
    }
}