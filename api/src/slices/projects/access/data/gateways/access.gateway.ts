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

    async findByProjectId(projectId: string, page: number, limit: number, filters?: { environment?: string; accessLevel?: string; sortBy?: string; sortOrder?: 'asc' | 'desc' }): Promise<{ data: IAccessRecord[]; total: number }> {
        const where: any = { projectId };
        if (filters?.environment) {
            where.environment = filters.environment;
        }
        if (filters?.accessLevel) {
            where.accessLevel = filters.accessLevel;
        }

        const allowedSortFields = ['createdAt', 'serviceName'];
        const sortBy = (filters?.sortBy && allowedSortFields.includes(filters.sortBy)) ? filters.sortBy : 'createdAt';
        const sortOrder = filters?.sortOrder || 'desc';

        const [results, total] = await Promise.all([
            this.prisma.access.findMany({
                where,
                skip: (page - 1) * limit,
                take: limit,
                orderBy: { [sortBy]: sortOrder },
            }),
            this.prisma.access.count({ where }),
        ]);
        return { data: results as unknown as IAccessRecord[], total };
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
