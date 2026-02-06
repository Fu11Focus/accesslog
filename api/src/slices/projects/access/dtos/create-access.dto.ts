import { ApiProperty } from "@nestjs/swagger";
import { IsEnum, IsOptional, IsString } from "class-validator";
import { AccessEnvironment, AccessLevel } from "../domain/interfaces";


export class CreateAccessDto {
    @ApiProperty()
    @IsString()
    projectId: string;

    @ApiProperty()
    @IsString()
    @IsOptional()
    serviceName?: string;

    @ApiProperty()
    @IsString()
    @IsOptional()
    serviceUrl?: string;

    @ApiProperty()
    @IsEnum(AccessEnvironment)
    environment: AccessEnvironment;

    @ApiProperty()
    @IsEnum(AccessLevel)
    @IsOptional()
    accessLevel: AccessLevel;

    @ApiProperty()
    @IsString()
    @IsOptional()
    login: string;

    @ApiProperty()
    @IsString()
    password: string;

    @ApiProperty()
    @IsString()
    @IsOptional()
    notes?: string;

    @ApiProperty()
    @IsString()
    @IsOptional()
    owner?: string;
}