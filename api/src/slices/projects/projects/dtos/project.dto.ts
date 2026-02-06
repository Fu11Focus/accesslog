import { ApiProperty } from "@nestjs/swagger";


export class ProjectDto {
    @ApiProperty()
    id: string;

    @ApiProperty()
    name: string;

    @ApiProperty({ required: false })
    clientName: string;

    @ApiProperty()
    status: string;

    @ApiProperty({ required: false })
    description: string;

    @ApiProperty()
    createdAt: Date;

    @ApiProperty()
    updatedAt: Date;
}