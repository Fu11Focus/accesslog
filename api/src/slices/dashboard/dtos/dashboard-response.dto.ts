import { ApiProperty } from "@nestjs/swagger";

class EnvironmentsDto {
  @ApiProperty()
  production: number;

  @ApiProperty()
  staging: number;

  @ApiProperty()
  development: number;
}

class DashboardStatsDto {
  @ApiProperty()
  totalProjects: number;

  @ApiProperty()
  totalCredentials: number;

  @ApiProperty({ type: EnvironmentsDto })
  environments: EnvironmentsDto;

  @ApiProperty()
  activities: number;
}

class DashboardProjectDto {
  @ApiProperty()
  id: string;

  @ApiProperty()
  name: string;

  @ApiProperty({ required: false })
  clientName?: string;

  @ApiProperty()
  status: string;

  @ApiProperty({ required: false })
  description?: string;

  @ApiProperty()
  createdAt: Date;

  @ApiProperty()
  updatedAt: Date;

  @ApiProperty()
  credentialsCount: number;
}

class DashboardActivityDto {
  @ApiProperty()
  id: string;

  @ApiProperty()
  accessId: string;

  @ApiProperty()
  userId: string;

  @ApiProperty()
  action: string;

  @ApiProperty()
  createdAt: Date;

  @ApiProperty()
  updatedAt: Date;

  @ApiProperty({ required: false })
  serviceName?: string;

  @ApiProperty({ required: false })
  projectName?: string;
}

export class DashboardResponseDto {
  @ApiProperty({ type: DashboardStatsDto })
  stats: DashboardStatsDto;

  @ApiProperty({ type: [DashboardProjectDto] })
  recentProjects: DashboardProjectDto[];

  @ApiProperty({ type: [DashboardActivityDto] })
  recentActivities: DashboardActivityDto[];
}
