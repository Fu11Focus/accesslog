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
    projectId: string;

    @ApiProperty()
    @IsOptional()
    serviceName?: string;

    @ApiProperty()
    @IsOptional()
    serviceUrl?: string;

    @ApiProperty()
    @IsEnum(AccessEnvironment)
    environment?: AccessEnvironment;

    @ApiProperty()
    @IsEnum(AccessLevel)
    @IsOptional()
    accessLevel?: AccessLevel;

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
