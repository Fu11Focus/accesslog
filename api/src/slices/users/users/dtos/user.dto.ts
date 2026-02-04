import { ApiProperty } from "@nestjs/swagger";

export class UserDto {
    @ApiProperty()
    id: string;

    @ApiProperty()
    email: string;

    @ApiProperty()
    plan: 'FREE' | 'PRO';

    @ApiProperty()
    createdAt: Date;

    @ApiProperty()
    updatedAt: Date;
}