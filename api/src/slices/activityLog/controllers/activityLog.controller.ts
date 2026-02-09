import { IActivityLogGateway } from "#activityLog/domain/activityLog.gateway";
import { AuthGuard } from "#users/auth/guards";
import { Controller, Get, Param, UseGuards } from "@nestjs/common";
import { ApiBearerAuth, ApiOperation, ApiTags } from "@nestjs/swagger";



@Controller('activity-log')
@ApiTags('activity-log')
@UseGuards(AuthGuard)
@ApiBearerAuth()
export class ActivityLogController {
    constructor(private readonly activityLogGateway: IActivityLogGateway) { }

    @Get('access/:accessId')
    @ApiOperation({
        description: 'Get all activities for a specific access',
        operationId: 'getActivitiesByAccessId'
    })
    async getActivitiesByAccessId(@Param('accessId') accessId: string) {
        return this.activityLogGateway.getActivitiesByAccessId(accessId);
    }

    @Get('project/:projectId')
    @ApiOperation({
        description: 'Get all activities for a specific project',
        operationId: 'getActivitiesByProjectId'
    })
    async getActivitiesByProjectId(@Param('projectId') projectId: string) {
        return this.activityLogGateway.getActivitiesByProjectId(projectId);
    }
}