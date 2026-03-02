import { IActivityLog } from "#activityLog/domain/interfaces/activityLog.interface";
import { IProject } from "#projects/projects/domain/interfaces";
import { ApiProperty } from "@nestjs/swagger";

export class DashboardDto {
    @ApiProperty()
     stats: {
        totalProjects: number;
        totalCredentials: number;
        environments: {
          production: number;
          staging: number;
          development: number;
        };
        activities: number;
      };
      @ApiProperty()
      recentProjects: (IProject & { credentialsCount: number })[];
      @ApiProperty()
      recentActivities: (IActivityLog & { serviceName?: string; projectName?: string })[];
    
}