import { Injectable } from "@nestjs/common";
import { IDashboardGateway } from "./dashboard.gateway.interface";
import { IDashboardData } from "./dashboard.types";

@Injectable()
export class DashboardService {
  constructor(
    private readonly gateway: IDashboardGateway,
  ) {}

  async getDashboardData(userId: string): Promise<IDashboardData> {
    return this.gateway.getDashboardData(userId);
  }
}
