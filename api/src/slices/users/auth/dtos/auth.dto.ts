import { ApiProperty } from "@nestjs/swagger";

export class AuthDto {
    @ApiProperty()
    email: string;

    @ApiProperty()
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
    @ApiProperty()
    refreshToken: string;
}