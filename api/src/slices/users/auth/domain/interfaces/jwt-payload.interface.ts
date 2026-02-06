// Payload який ми передаємо при створенні токена
export interface IJwtPayload {
    sub: string; // user.id
    id?: string;
    email: string;
    encryptionKey: string;
}

export interface IJwtPayloadVerified extends IJwtPayload {
    iat: number; // issued at
    exp: number; // expires at
}