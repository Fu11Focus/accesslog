import { ApiProperty } from "@nestjs/swagger";
import { IsString, IsOptional, IsEnum, IsNotEmpty } from "class-validator";
import { ProjectStatus } from "#projects/projects/domain/interfaces";

export class CreateProjectDto {
    @ApiProperty()
    @IsString()
    @IsNotEmpty()
    name: string;

    @ApiProperty({ required: false })
    @IsOptional()
    @IsString()
    clientName?: string;

    @ApiProperty({ enum: ProjectStatus })
    @IsEnum(ProjectStatus)
    status: ProjectStatus;

    @ApiProperty({ required: false })
    @IsOptional()
    @IsString()
    description?: string;
}