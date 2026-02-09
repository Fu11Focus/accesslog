import { ApiProperty } from "@nestjs/swagger";
import { IsString, IsOptional, IsEnum, IsNotEmpty } from "class-validator";
import { ProjectStatus } from "#projects/projects/domain/interfaces";

export class UpdateProjectDto {
    @ApiProperty({ required: false })
    @IsOptional()
    @IsString()
    @IsNotEmpty()
    name?: string;

    @ApiProperty({ required: false })
    @IsOptional()
    @IsString()
    @IsNotEmpty()
    clientName?: string;

    @ApiProperty({ required: false })
    @IsOptional()
    @IsEnum(ProjectStatus)
    status?: ProjectStatus;

    @ApiProperty({ required: false })
    @IsOptional()
    @IsString()
    @IsNotEmpty()
    description?: string;
}