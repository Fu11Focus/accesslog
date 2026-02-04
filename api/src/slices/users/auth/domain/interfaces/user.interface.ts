export interface IUser {
    id: string;
    email: string;
    plan: 'FREE' | 'PRO';
    createdAt: Date;
    updatedAt: Date;
}