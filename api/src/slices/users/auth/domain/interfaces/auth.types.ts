import { IUser } from "./user.interface";

export interface ILoginResult {
    user: IUser;
    accessToken: string;
    refreshToken: string;
}

export interface ITwoFactorLoginResult {
    requiresTwoFactor: true;
    sessionToken: string;
}

export interface IRefreshTokenResult {
    accessToken: string;
    refreshToken: string;
}