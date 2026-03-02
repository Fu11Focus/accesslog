import { ILoginResult, ITwoFactorLoginResult, IUser } from "#users/auth/domain";


export abstract class IAuthService {
    abstract login(email: string, password: string): Promise<ILoginResult | ITwoFactorLoginResult>;
    abstract register(email: string, password: string): Promise<IUser>;
    abstract verifyPassword(userId: string, password: string): Promise<boolean>;
    abstract changePassword(userId: string, currentPassword: string, newPassword: string): Promise<ILoginResult>;
}
