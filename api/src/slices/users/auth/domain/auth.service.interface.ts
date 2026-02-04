import { ILoginResult, IUser } from "#users/auth/domain";


export abstract class IAuthService {
    abstract login(email: string, password: string): Promise<ILoginResult>;
    abstract register(email: string, password: string): Promise<IUser>;
    abstract verifyPassword(userId: string, password: string): Promise<boolean>;
}
