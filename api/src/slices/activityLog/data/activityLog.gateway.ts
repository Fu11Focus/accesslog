import { IActivityLogGateway } from "#activityLog/domain/activityLog.gateway";
import { IActivityLog } from "#activityLog/domain/interfaces/activityLog.interface";
import { PrismaService } from "#prisma/prisma.service";
import { Injectable } from "@nestjs/common";
import { ActionLogMapper } from "./activityLog.mapper";
import { ICreateActivityLog } from "#activityLog/domain/interfaces/createActivityLog.interface";


@Injectable()
export class ActivityLogGateway implements IActivityLogGateway {
    constructor(
        private readonly prisma: PrismaService,
        private readonly mapper: ActionLogMapper
    ) { }

    async createActivityLog(data: ICreateActivityLog): Promise<IActivityLog> {
        const activity = await this.prisma.activityLog.create({ data });
        return this.mapper.toData(activity);
    }

    async getActivitiesByAccessId(accessId: string): Promise<IActivityLog[]> {
        const activities = await this.prisma.activityLog.findMany({ where: { accessId } });
        return activities.map(activity => this.mapper.toData(activity));
    }

    async getActivitiesByProjectId(projectId: string): Promise<IActivityLog[]> {
        const activities = await this.prisma.activityLog.findMany({
            where: {
                access: {
                    projectId
                }
            }
        });
        return activities.map(activity => this.mapper.toData(activity));
    }
}