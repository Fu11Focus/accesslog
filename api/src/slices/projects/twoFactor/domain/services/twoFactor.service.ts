import { ForbiddenException, Injectable, NotFoundException } from "@nestjs/common";
import { ITwoFactorService } from "../interfaces/twoFactor.service.interface";
import { ICreateTwoFactor, ITwoFactor, IUpdateTwoFactor } from "../interfaces";
import { ITwoFactorGateway } from "../gateways/twoFactor.gateway";


@Injectable()
export class TwoFactorService implements ITwoFactorService {
    constructor(
        private readonly gateway: ITwoFactorGateway,
    ) { }

    async createTwoFactor(data: ICreateTwoFactor, userId: string): Promise<ITwoFactor> {
        const isOwner = await this.gateway.accessBelongsToUser(data.accessId, userId);
        if (!isOwner) {
            throw new ForbiddenException('Access not found');
        }
        return this.gateway.create(data);
    }

    async getTwoFactorByAccessId(accessId: string, userId: string): Promise<ITwoFactor> {
        const isOwner = await this.gateway.accessBelongsToUser(accessId, userId);
        if (!isOwner) {
            throw new ForbiddenException('Access not found');
        }
        const result = await this.gateway.findByAccessId(accessId);
        if (!result) {
            throw new NotFoundException('Two-factor not found');
        }
        return result;
    }

    async getTwoFactorById(id: string, userId: string): Promise<ITwoFactor> {
        const isOwner = await this.gateway.belongsToUser(id, userId);
        if (!isOwner) {
            throw new ForbiddenException('Two-factor not found');
        }
        const result = await this.gateway.findById(id);
        if (!result) {
            throw new NotFoundException('Two-factor not found');
        }
        return result;
    }

    async updateTwoFactor(id: string, data: IUpdateTwoFactor, userId: string): Promise<ITwoFactor> {
        const isOwner = await this.gateway.belongsToUser(id, userId);
        if (!isOwner) {
            throw new ForbiddenException('Two-factor not found');
        }
        return this.gateway.update(id, data);
    }

    async deleteTwoFactorById(id: string, userId: string): Promise<void> {
        const isOwner = await this.gateway.belongsToUser(id, userId);
        if (!isOwner) {
            throw new ForbiddenException('Two-factor not found');
        }
        return this.gateway.delete(id);
    }
}
