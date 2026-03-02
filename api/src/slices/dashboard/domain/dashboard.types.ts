import { IActivityLog } from "#activityLog/domain/interfaces/activityLog.interface";
import { IProject } from "#projects/projects/domain/interfaces";

export interface IDashboardData {
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
  recentProjects: (IProject & { credentialsCount: number })[];
  recentActivities: (IActivityLog & { serviceName?: string; projectName?: string })[];
}