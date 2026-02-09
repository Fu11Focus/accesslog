import { TwoFactorType } from "./twoFactor.interface";


export interface ICreateTwoFactor {
    accessId: string;
    type: TwoFactorType;
    enabled: boolean;
}