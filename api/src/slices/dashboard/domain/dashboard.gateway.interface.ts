import { IDashboardData } from "./dashboard.types";

export abstract class IDashboardGateway {
  abstract getDashboardData(userId: string): Promise<IDashboardData>;
}