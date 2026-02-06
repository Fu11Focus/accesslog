import { Access } from "@prisma/client";
import { AccessEnvironment, IAccess, AccessLevel } from "../domain/interfaces";
import { Injectable } from "@nestjs/common";


@Injectable()
export class AccessMapper {
    toData(access: Access): IAccess {
        return {
            id: access.id,
            projectId: access.projectId,
            serviceName: access.serviceName || undefined,
            serviceUrl: access.serviceUrl || undefined,
            environment: access.environment as AccessEnvironment,
            accessLevel: access.accessLevel as AccessLevel,
            login: access.login,
            notes: access.notes || undefined,
            owner: access.owner || undefined,
            createdAt: access.createdAt,
            updatedAt: access.updatedAt
        }
    }
}