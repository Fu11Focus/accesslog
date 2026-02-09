import { Module } from "@nestjs/common";
import { PrismaModule } from "#prisma/prisma.module";
import { IActivityLogGateway } from "./domain/activityLog.gateway";
import { ActivityLogGateway } from "./data/activityLog.gateway";
import { ActionLogMapper } from "./data/activityLog.mapper";
import { ActivityLogController } from "./controllers/activityLog.controller";

@Module({
    imports: [PrismaModule],
    controllers: [ActivityLogController],
    providers: [
        { provide: IActivityLogGateway, useClass: ActivityLogGateway },
        ActionLogMapper,
    ],
    exports: [IActivityLogGateway],
})
export class ActivityLogModule { }
