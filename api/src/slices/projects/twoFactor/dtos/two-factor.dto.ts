import { ApiProperty } from "@nestjs/swagger";
import { IsBoolean, IsDate, IsEnum, IsString } from "class-validator";
import { ITwoFactor, TwoFactorType } from "../domain/interfaces";


export class TwoFactorDto implements ITwoFactor {
    @ApiProperty()
    @IsString()
    id: string;

    @ApiProperty()
    @IsString()
    accessId: string;

    @ApiProperty()
    @IsEnum(TwoFactorType)
    type: TwoFactorType;

    @ApiProperty()
    @IsBoolean()
    enabled: boolean;

    @ApiProperty()
    @IsDate()
    createdAt: Date;

    @ApiProperty()
    @IsDate()
    updatedAt: Date;
}