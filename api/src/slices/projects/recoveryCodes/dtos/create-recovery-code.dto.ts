import { ApiProperty } from "@nestjs/swagger";
import { IsOptional, IsString } from "class-validator";
import { ICreateRecoveryCode } from "../domain/interfaces/createRecoveryCode.interface";

export class CreateRecoveryCodeDto implements ICreateRecoveryCode {
    @ApiProperty()
    @IsString()
    twoFactorId: string;

    @ApiProperty()
    @IsString()
    code: string;
}