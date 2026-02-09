import { PrismaService } from "#prisma/prisma.service";
import { Injectable } from "@nestjs/common";
import { IAccessGateway, IAccessRecord } from "../../domain/gateways/access.gateway";

@Injectable()
export class AccessGateway implements IAccessGateway {
    constructor(private readonly prisma: PrismaService) { }

    async create(data: {
        projectId: string;
        serviceName?: string;
        serviceUrl?: string;
        environment: string;
        accessLevel?: string;
        login: string;
        passwordEncrypted: string;
        notes?: string;
        owner?: string;
    }): Promise<IAccessRecord> {
        return this.prisma.access.create({ data: data as any }) as unknown as Promise<IAccessRecord>;
    }

    async findById(id: string): Promise<IAccessRecord | null> {
        return this.prisma.access.findUnique({ where: { id } }) as unknown as Promise<IAccessRecord | null>;
    }

    async findByProjectId(projectId: string): Promise<IAccessRecord[]> {
        return this.prisma.access.findMany({ where: { projectId } }) as unknown as Promise<IAccessRecord[]>;
    }

    async update(id: string, data: Partial<Omit<IAccessRecord, 'id' | 'createdAt' | 'updatedAt'>>): Promise<IAccessRecord> {
        return this.prisma.access.update({ where: { id }, data: data as any }) as unknown as Promise<IAccessRecord>;
    }

    async delete(id: string): Promise<void> {
        await this.prisma.access.delete({ where: { id } });
    }

    async projectExists(projectId: string): Promise<boolean> {
        const project = await this.prisma.project.findUnique({ where: { id: projectId } });
        return !!project;
    }
}
