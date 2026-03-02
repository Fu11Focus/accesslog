import { ApiProperty } from "@nestjs/swagger";
import { IsEnum, IsOptional, IsString } from "class-validator";
import { AccessEnvironment } from "../domain/interfaces";
import { AccessLevel } from "../domain/interfaces";

export class UpdateAccessDto {
    @ApiProperty()
    @IsString()
    id: string;

    @ApiProperty()
    @IsString()
    @IsOptional()
    serviceName?: string;

    @ApiProperty()
    @IsOptional()
    @IsString()
    serviceUrl?: string;

    @ApiProperty({ enum: AccessEnvironment, enumName: 'AccessEnvironment' })
    @IsEnum(AccessEnvironment)
    environment: AccessEnvironment;

    @ApiProperty({ enum: AccessLevel, enumName: 'AccessLevel' })
    @IsEnum(AccessLevel)
    accessLevel: AccessLevel;

    @ApiProperty()
    @IsString()
    login: string;

    @ApiProperty()
    @IsString()
    password: string;

    @ApiProperty()
    @IsOptional()
    @IsString()
    notes?: string;

    @ApiProperty()
    @IsOptional()
    @IsString()
    owner?: string;
}
