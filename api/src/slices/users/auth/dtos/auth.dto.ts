import { ApiProperty } from "@nestjs/swagger";
import { IsEmail, IsString, IsNotEmpty, IsOptional, MinLength } from "class-validator";

export class AuthDto {
    @ApiProperty()
    @IsEmail()
    email: string;

    @ApiProperty()
    @IsString()
    @IsNotEmpty()
    @MinLength(6)
    password: string;
}


export class LoginResponseDto {
    @ApiProperty()
    accessToken: string;

    @ApiProperty()
    refreshToken: string;

    @ApiProperty()
    tokenType: string;
}

export class RefreshTokenDto {
    @ApiProperty({ required: false })
    @IsString()
    @IsOptional()
    refreshToken?: string;
}

export class RefreshResponseDto {
    @ApiProperty()
    accessToken: string;

    @ApiProperty()
    refreshToken: string;
}

export class MeResponseDto {
    @ApiProperty()
    id: string;

    @ApiProperty()
    email: string;
}

export class MessageResponseDto {
    @ApiProperty()
    message: string;
}