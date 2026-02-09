import { Injectable, NotFoundException } from "@nestjs/common";
import { ITwoFactorService } from "../interfaces/twoFactor.service.interface";
import { ICreateTwoFactor, ITwoFactor, IUpdateTwoFactor } from "../interfaces";
import { ITwoFactorGateway } from "../gateways/twoFactor.gateway";


@Injectable()
export class TwoFactorService implements ITwoFactorService {
    constructor(
        private readonly gateway: ITwoFactorGateway,
    ) { }

    async createTwoFactor(data: ICreateTwoFactor): Promise<ITwoFactor> {
        const accessExists = await this.gateway.accessExists(data.accessId);
        if (!accessExists) {
            throw new NotFoundException('Access not found');
        }
        return this.gateway.create(data);
    }

    async getTwoFactorByAccessId(accessId: string): Promise<ITwoFactor> {
        const result = await this.gateway.findByAccessId(accessId);
        if (!result) {
            throw new NotFoundException('Two-factor not found');
        }
        return result;
    }

    async getTwoFactorById(id: string): Promise<ITwoFactor> {
        const result = await this.gateway.findById(id);
        if (!result) {
            throw new NotFoundException('Two-factor not found');
        }
        return result;
    }

    async updateTwoFactor(id: string, data: IUpdateTwoFactor): Promise<ITwoFactor> {
        return this.gateway.update(id, data);
    }

    async deleteTwoFactorById(id: string): Promise<void> {
        return this.gateway.delete(id);
    }
}
