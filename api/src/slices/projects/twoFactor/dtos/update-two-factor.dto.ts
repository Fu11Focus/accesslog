import { IUpdateTwoFactor, TwoFactorType } from "../domain/interfaces";
import { IsBoolean, IsEnum, IsString } from "class-validator";
import { ApiProperty } from "@nestjs/swagger";

export class UpdateTwoFactorDto implements IUpdateTwoFactor {
    @ApiProperty()
    @IsEnum(TwoFactorType)
    type: TwoFactorType;

    @ApiProperty()
    @IsBoolean()
    enabled: boolean;
}