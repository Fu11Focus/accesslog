import { DashboardService } from "#dashboard/domain";
import { DashboardResponseDto } from "#dashboard/dtos/dashboard-response.dto";
import { User } from "#users/auth/decorators";
import { AuthGuard } from "#users/auth/guards";
import { Controller, Get, UseGuards } from "@nestjs/common";
import { ApiBearerAuth, ApiOkResponse, ApiOperation, ApiTags } from "@nestjs/swagger";

@Controller("dashboard")
@ApiTags("Dashboard")
@UseGuards(AuthGuard)
@ApiBearerAuth()
export class DashboardController {
  constructor(
    private readonly dashboardService: DashboardService
  ) {}

  @Get()
  @ApiOperation({
    description: "Get dashboard data",
    operationId: "getDashboardData",
  })
  @ApiOkResponse({ type: DashboardResponseDto })
  getDashboardData(@User("id") userId: string): Promise<DashboardResponseDto> {
    return this.dashboardService.getDashboardData(userId);
  }
}