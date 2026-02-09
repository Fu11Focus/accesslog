import { ICreateTwoFactor, IUpdateTwoFactor } from "./";
import { ITwoFactor } from "./twoFactor.interface";

export abstract class ITwoFactorService {
    abstract createTwoFactor(data: ICreateTwoFactor): Promise<ITwoFactor>;
    abstract getTwoFactorByAccessId(accessId: string): Promise<ITwoFactor>;
    abstract getTwoFactorById(id: string): Promise<ITwoFactor>;
    abstract updateTwoFactor(id: string, data: IUpdateTwoFactor): Promise<ITwoFactor>;
    abstract deleteTwoFactorById(id: string): Promise<void>;
}