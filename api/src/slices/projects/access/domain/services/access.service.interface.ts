import { IAccess, ICreateAccess, IUpdateAccess } from "../interfaces";

export abstract class IAccessService {
    abstract createAccess(access: ICreateAccess, encryptionKey: string, userId: string): Promise<IAccess>
    abstract updateAccess(access: IUpdateAccess, encryptionKey: string, userId: string): Promise<IAccess>
    abstract getAccessByProjectId(projectId: string, encryptionKey: string): Promise<IAccess[]>
    abstract getAccessById(id: string, encryptionKey: string): Promise<IAccess>
    abstract deleteAccessById(id: string, userId: string): Promise<void>
}