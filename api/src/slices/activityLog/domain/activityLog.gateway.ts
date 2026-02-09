import { IActivityLog } from "./interfaces/activityLog.interface";
import { ICreateActivityLog } from "./interfaces/createActivityLog.interface";

export abstract class IActivityLogGateway {
    abstract createActivityLog(data: ICreateActivityLog): Promise<IActivityLog>;
    abstract getActivitiesByAccessId(accessId: string): Promise<IActivityLog[]>;
    abstract getActivitiesByProjectId(projectId: string): Promise<IActivityLog[]>;
}