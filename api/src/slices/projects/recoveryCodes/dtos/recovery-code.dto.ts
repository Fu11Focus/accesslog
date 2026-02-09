import { IsBoolean, IsDate, IsString } from "class-validator";
import { IRecoveryCode } from "../domain/interfaces/recoveryCode.interface";
import { ApiProperty } from "@nestjs/swagger";

export class RecoveryCodeDto implements IRecoveryCode {
    @ApiProperty()
    @IsString()
    id: string;

    @ApiProperty()
    @IsString()
    twoFactorId: string;

    @ApiProperty()
    @IsString()
    code?: string;

    @ApiProperty()
    @IsBoolean()
    used: boolean;

    @ApiProperty()
    @IsDate()
    usedAt?: Date;

    @ApiProperty()
    @IsDate()
    createdAt: Date;
    updatedAt: Date;
}