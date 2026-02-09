import { TwoFactorType } from "./twoFactor.interface";

export interface IUpdateTwoFactor {
    type?: TwoFactorType;
    enabled?: boolean;
}