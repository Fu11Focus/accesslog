import { IAccess, ICreateAccess, IUpdateAccess } from "../interfaces";
import { IPaginatedResult } from "#shared/interfaces/paginated-result.interface";

export abstract class IAccessService {
    abstract createAccess(access: ICreateAccess, encryptionKey: string, userId: string): Promise<IAccess>
    abstract updateAccess(access: IUpdateAccess, encryptionKey: string, userId: string): Promise<IAccess>
    abstract getAccessByProjectId(projectId: string, encryptionKey: string, page: number, limit: number, filters?: { environment?: string; accessLevel?: string; sortBy?: string; sortOrder?: 'asc' | 'desc' }): Promise<IPaginatedResult<IAccess>>
    abstract getAccessById(id: string, encryptionKey: string): Promise<IAccess>
    abstract deleteAccessById(id: string, userId: string): Promise<void>
}