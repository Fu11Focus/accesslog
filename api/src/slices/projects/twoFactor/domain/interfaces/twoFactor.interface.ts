

export interface ITwoFactor {
    id: string;
    accessId: string;

    type: TwoFactorType;
    enabled: boolean;

    createdAt: Date;
    updatedAt: Date;
}

export enum TwoFactorType {
    APP = 'APP',
    SMS = 'SMS',
    HARDWARE = 'HARDWARE',
}