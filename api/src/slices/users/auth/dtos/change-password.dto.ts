import { ApiProperty } from "@nestjs/swagger";
import { IsString, IsNotEmpty, MinLength } from "class-validator";

export class ChangePasswordDto {
    @ApiProperty()
    @IsString()
    @IsNotEmpty()
    @MinLength(6)
    currentPassword: string;

    @ApiProperty()
    @IsString()
    @IsNotEmpty()
    @MinLength(6)
    newPassword: string;
}
