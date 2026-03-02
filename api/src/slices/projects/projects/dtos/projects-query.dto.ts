import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsIn, IsOptional } from 'class-validator';
import { PaginationQueryDto } from '#shared/dtos/pagination-query.dto';

export class ProjectsQueryDto extends PaginationQueryDto {
    @ApiPropertyOptional({ enum: ['ACTIVE', 'ARCHIVED'] })
    @IsOptional()
    @IsIn(['ACTIVE', 'ARCHIVED'])
    status?: 'ACTIVE' | 'ARCHIVED';
}
