import { IDashboardData, IDashboardGateway } from "#dashboard/domain";
import { PrismaService } from "#prisma/prisma.service";
import { Injectable } from "@nestjs/common";
import { ProjectStatus } from "#projects/projects/domain/interfaces";
import { ActionType } from "#activityLog/domain/interfaces/activityLog.interface";

@Injectable()
export class DashboardGateway implements IDashboardGateway {
  constructor(
    private readonly prisma: PrismaService,
  ) {}

  async getDashboardData(userId: string): Promise<IDashboardData> {
    const [projects, credentialStats, totalCredentials, totalActivities, recentActivities] = await Promise.all([
      this.prisma.project.findMany({
        where: { userId },
        take: 4,
        orderBy: { updatedAt: 'desc' },
        include: { _count: { select: { access: true } } },
      }),

      this.prisma.access.groupBy({
        by: ['environment'],
        where: { project: { userId } },
        _count: true,
      }),

      this.prisma.access.count({
        where: { project: { userId } },
      }),

      this.prisma.activityLog.count({
        where: { userId },
      }),

      this.prisma.activityLog.findMany({
        where: { userId },
        take: 6,
        orderBy: { createdAt: 'desc' },
        include: { access: { select: { serviceName: true, project: { select: { name: true } } } } },
      }),
    ]);

    const envMap = Object.fromEntries(credentialStats.map((s) => [s.environment, s._count]));

    return {
      stats: {
        totalProjects: projects.length,
        totalCredentials,
        environments: {
          production: envMap['PRODUCTION'] ?? 0,
          staging: envMap['STAGING'] ?? 0,
          development: envMap['DEVELOPMENT'] ?? 0,
        },
        activities: totalActivities,
      },
      recentProjects: projects.map((p) => ({
        id: p.id,
        name: p.name,
        clientName: p.clientName ?? undefined,
        status: p.status as ProjectStatus,
        description: p.description ?? undefined,
        createdAt: p.createdAt,
        updatedAt: p.updatedAt,
        credentialsCount: p._count.access,
      })),
      recentActivities: recentActivities.map((a) => ({
        id: a.id,
        accessId: a.accessId,
        userId: a.userId,
        action: a.action as ActionType,
        createdAt: a.createdAt,
        updatedAt: a.updatedAt,
        serviceName: a.access?.serviceName ?? undefined,
        projectName: a.access?.project?.name ?? undefined,
      })),
    };
  }
}