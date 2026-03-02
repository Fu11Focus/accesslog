import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsIn, IsOptional } from 'class-validator';
import { PaginationQueryDto } from '#shared/dtos/pagination-query.dto';

export class AccessQueryDto extends PaginationQueryDto {
    @ApiPropertyOptional({ enum: ['PRODUCTION', 'STAGING', 'DEVELOPMENT'] })
    @IsOptional()
    @IsIn(['PRODUCTION', 'STAGING', 'DEVELOPMENT'])
    environment?: 'PRODUCTION' | 'STAGING' | 'DEVELOPMENT';

    @ApiPropertyOptional({ enum: ['ADMIN', 'EDITOR', 'VIEWER'] })
    @IsOptional()
    @IsIn(['ADMIN', 'EDITOR', 'VIEWER'])
    accessLevel?: 'ADMIN' | 'EDITOR' | 'VIEWER';
}
