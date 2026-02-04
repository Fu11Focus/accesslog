import { IUser } from "./user.interface";

export interface ILoginResult {
    user: IUser;
    accessToken: string;
    refreshToken: string;
}

export interface IRefreshTokenResult {
    accessToken: string;
    refreshToken: string;
}