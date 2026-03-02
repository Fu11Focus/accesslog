/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { DashboardActivityDto } from './DashboardActivityDto';
import type { DashboardProjectDto } from './DashboardProjectDto';
import type { DashboardStatsDto } from './DashboardStatsDto';
export type DashboardResponseDto = {
    stats: DashboardStatsDto;
    recentProjects: Array<DashboardProjectDto>;
    recentActivities: Array<DashboardActivityDto>;
};

