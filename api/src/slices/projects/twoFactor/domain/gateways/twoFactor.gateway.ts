import { ICreateTwoFactor, ITwoFactor, IUpdateTwoFactor } from '../interfaces';

export abstract class ITwoFactorGateway {
    abstract create(data: ICreateTwoFactor): Promise<ITwoFactor>;
    abstract findById(id: string): Promise<ITwoFactor | null>;
    abstract findByAccessId(accessId: string): Promise<ITwoFactor | null>;
    abstract update(id: string, data: IUpdateTwoFactor): Promise<ITwoFactor>;
    abstract delete(id: string): Promise<void>;
    abstract accessExists(accessId: string): Promise<boolean>;
}
