import { IActivityLog, ActionType } from "#activityLog/domain/interfaces/activityLog.interface";
import { Injectable } from "@nestjs/common";
import { ActivityLog } from "@prisma/client";

@Injectable()
export class ActionLogMapper {
    toData(data: ActivityLog): IActivityLog {
        return {
            id: data.id,
            accessId: data.accessId,
            userId: data.userId,
            action: data.action as ActionType,
            createdAt: data.createdAt,
            updatedAt: data.updatedAt,
        };
    }
}