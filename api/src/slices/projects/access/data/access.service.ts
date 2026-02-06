import { PrismaService } from "#prisma/prisma.service";
import { Injectable, NotFoundException } from "@nestjs/common";
import { IAccess, ICreateAccess, IUpdateAccess } from "../domain/interfaces";
import { IAccessService } from "../domain/services/access.service.interface";
import { AccessMapper } from "./access.mapper";
import { EncryptionService } from "#shared/domain/services/encryption.service";



@Injectable()
export class AccessService implements IAccessService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly mapper: AccessMapper,
        private readonly encryptionService: EncryptionService
    ) { }

    async createAccess(access: ICreateAccess, encryptionKey: string): Promise<IAccess> {
        const project = await this.prisma.project.findUnique({
            where: {
                id: access.projectId
            }
        })

        if (!project) {
            throw new NotFoundException("Project not found");
        }

        const passwordEncrypted = this.encryptionService.encrypt(access.password, encryptionKey);
        const { password, ...accessData } = access;

        const result = await this.prisma.access.create({
            data: {
                ...accessData,
                projectId: access.projectId,
                passwordEncrypted
            }
        })

        return { ...this.mapper.toData(result), password };
    }

    async updateAccess(access: IUpdateAccess, encryptionKey: string): Promise<IAccess> {
        const { password, ...accessData } = access;
        const result = await this.prisma.access.update({
            where: {
                id: access.id
            },
            data: {
                ...accessData,
                passwordEncrypted: this.encryptionService.encrypt(password, encryptionKey)
            }
        })

        return { ...this.mapper.toData(result), password };
    }

    async getAccessByProject(projectId: string, encryptionKey: string): Promise<IAccess[]> {
        const result = await this.prisma.access.findMany({
            where: {
                projectId
            }
        })

        return result.map((access) => ({ ...this.mapper.toData(access), password: this.encryptionService.decrypt(access.passwordEncrypted, encryptionKey) }));
    }

    async getAccessById(id: string, encryptionKey: string): Promise<IAccess> {
        const access = await this.prisma.access.findUnique({
            where: {
                id
            }
        })

        if (!access) {
            throw new Error("Access not found");
        }

        return { ...this.mapper.toData(access), password: this.encryptionService.decrypt(access.passwordEncrypted, encryptionKey) };
    }

    async deleteAccessById(id: string): Promise<void> {
        await this.prisma.access.delete({
            where: {
                id
            }
        })
    }
}