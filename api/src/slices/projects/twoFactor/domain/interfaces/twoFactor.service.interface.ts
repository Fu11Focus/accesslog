import { ICreateTwoFactor, IUpdateTwoFactor } from "./";
import { ITwoFactor } from "./twoFactor.interface";

export abstract class ITwoFactorService {
    abstract createTwoFactor(data: ICreateTwoFactor, userId: string): Promise<ITwoFactor>;
    abstract getTwoFactorByAccessId(accessId: string, userId: string): Promise<ITwoFactor>;
    abstract getTwoFactorById(id: string, userId: string): Promise<ITwoFactor>;
    abstract updateTwoFactor(id: string, data: IUpdateTwoFactor, userId: string): Promise<ITwoFactor>;
    abstract deleteTwoFactorById(id: string, userId: string): Promise<void>;
}
