import { PrismaService } from "#prisma/prisma.service";
import { Injectable } from "@nestjs/common";
import { ITwoFactorGateway } from "../../domain/gateways/twoFactor.gateway";
import { ICreateTwoFactor, ITwoFactor, IUpdateTwoFactor } from "../../domain/interfaces";
import { TwoFactorMapper } from "../twoFactor.mapper";

@Injectable()
export class TwoFactorGateway implements ITwoFactorGateway {
    constructor(
        private readonly prisma: PrismaService,
        private readonly mapper: TwoFactorMapper,
    ) { }

    async create(data: ICreateTwoFactor): Promise<ITwoFactor> {
        const result = await this.prisma.twoFactor.create({ data });
        return this.mapper.toData(result);
    }

    async findById(id: string): Promise<ITwoFactor | null> {
        const result = await this.prisma.twoFactor.findUnique({ where: { id } });
        return result ? this.mapper.toData(result) : null;
    }

    async findByAccessId(accessId: string): Promise<ITwoFactor | null> {
        const result = await this.prisma.twoFactor.findUnique({ where: { accessId } });
        return result ? this.mapper.toData(result) : null;
    }

    async update(id: string, data: IUpdateTwoFactor): Promise<ITwoFactor> {
        const result = await this.prisma.twoFactor.update({ where: { id }, data });
        return this.mapper.toData(result);
    }

    async delete(id: string): Promise<void> {
        await this.prisma.twoFactor.delete({ where: { id } });
    }

    async accessExists(accessId: string): Promise<boolean> {
        const access = await this.prisma.access.findUnique({ where: { id: accessId } });
        return !!access;
    }
}
