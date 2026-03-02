import { Injectable, NotFoundException } from "@nestjs/common";
import { IAccessService } from "./access.service.interface";
import { IAccess, ICreateAccess, IUpdateAccess, AccessEnvironment, AccessLevel } from "../interfaces";
import { IAccessGateway, IAccessRecord } from "../gateways/access.gateway";
import { EncryptionService } from "#shared/domain/services/encryption.service";
import { IActivityLogGateway } from "#activityLog/domain/activityLog.gateway";
import { ActionType } from "#activityLog/domain/interfaces/activityLog.interface";
import { IPaginatedResult } from "#shared/interfaces/paginated-result.interface";


@Injectable()
export class AccessService implements IAccessService {
    constructor(
        private readonly gateway: IAccessGateway,
        private readonly encryptionService: EncryptionService,
        private readonly activityLogGateway: IActivityLogGateway,
    ) { }

    async createAccess(access: ICreateAccess, encryptionKey: string, userId: string): Promise<IAccess> {
        const projectExists = await this.gateway.projectExists(access.projectId);
        if (!projectExists) {
            throw new NotFoundException("Project not found");
        }

        const { password, ...accessData } = access;
        const passwordEncrypted = this.encryptionService.encrypt(password, encryptionKey);

        const result = await this.gateway.create({
            ...accessData,
            passwordEncrypted,
        });

        await this.activityLogGateway.createActivityLog({
            accessId: result.id,
            userId,
            action: ActionType.accessCreated,
        });

        return { ...this.toData(result), password };
    }

    async updateAccess(access: IUpdateAccess, encryptionKey: string, userId: string): Promise<IAccess> {
        const { password, id, ...accessData } = access;
        const passwordEncrypted = this.encryptionService.encrypt(password, encryptionKey);

        const result = await this.gateway.update(id, {
            ...accessData,
            passwordEncrypted,
        });

        await this.activityLogGateway.createActivityLog({
            accessId: result.id,
            userId,
            action: ActionType.accessUpdated,
        });

        return { ...this.toData(result), password };
    }

    async getAccessByProjectId(projectId: string, encryptionKey: string, page: number, limit: number, filters?: { environment?: string; accessLevel?: string; sortBy?: string; sortOrder?: 'asc' | 'desc' }): Promise<IPaginatedResult<IAccess>> {
        const { data: records, total } = await this.gateway.findByProjectId(projectId, page, limit, filters);
        const data = records.map((record) => ({
            ...this.toData(record),
            password: this.encryptionService.decrypt(record.passwordEncrypted, encryptionKey),
        }));
        return {
            data,
            meta: { total, page, limit, totalPages: Math.ceil(total / limit) },
        };
    }

    async getAccessById(id: string, encryptionKey: string): Promise<IAccess> {
        const record = await this.gateway.findById(id);
        if (!record) {
            throw new NotFoundException("Access not found");
        }
        return {
            ...this.toData(record),
            password: this.encryptionService.decrypt(record.passwordEncrypted, encryptionKey),
        };
    }

    async deleteAccessById(id: string, userId: string): Promise<void> {
        const record = await this.gateway.findById(id);
        if (!record) {
            throw new NotFoundException("Access not found");
        }

        await this.activityLogGateway.createActivityLog({
            accessId: id,
            userId,
            action: ActionType.accessDeleted,
        });

        await this.gateway.delete(id);
    }

    private toData(record: IAccessRecord): IAccess {
        return {
            id: record.id,
            projectId: record.projectId,
            serviceName: record.serviceName || undefined,
            serviceUrl: record.serviceUrl || undefined,
            environment: record.environment as AccessEnvironment,
            accessLevel: record.accessLevel as AccessLevel,
            login: record.login,
            notes: record.notes || undefined,
            owner: record.owner || undefined,
            createdAt: record.createdAt,
            updatedAt: record.updatedAt,
        };
    }
}
