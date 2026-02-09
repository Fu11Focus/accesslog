import { ApiProperty } from "@nestjs/swagger";
import { IsBoolean, IsEnum, IsString } from "class-validator";
import { ICreateTwoFactor, TwoFactorType } from "../domain/interfaces";

export class CreateTwoFactorDto implements ICreateTwoFactor {
    @ApiProperty()
    @IsString()
    accessId: string;

    @ApiProperty()
    @IsEnum(TwoFactorType)
    type: TwoFactorType;

    @ApiProperty()
    @IsBoolean()
    enabled: boolean;
}