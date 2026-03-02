import { Module } from "@nestjs/common";
import { PrismaModule } from "#prisma/prisma.module";
import { DashboardService, IDashboardGateway } from "./domain";
import { DashboardGateway } from "./data/dashboard.gateway";
import { DashboardController } from "./controllers/dashboard.controller";

@Module({
  imports: [PrismaModule],
  providers: [
    { provide: IDashboardGateway, useClass: DashboardGateway },
    DashboardService,
  ],
  exports: [DashboardService],
  controllers: [DashboardController],
})
export class DashboardModule {}