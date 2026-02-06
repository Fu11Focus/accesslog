import { IsEnum, IsOptional, IsString } from "class-validator";
import { ApiProperty } from "@nestjs/swagger";
import { AccessEnvironment, AccessLevel } from "../domain/interfaces";



export class AccessDto {
    @ApiProperty()
    @IsString()
    id: string;

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
    login: string;

    @ApiProperty()
    @IsString()
    password: string;

    @ApiProperty()
    @IsOptional()
    notes?: string;

    @ApiProperty()
    @IsOptional()
    owner?: string;
}