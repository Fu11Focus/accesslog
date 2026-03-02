import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger";
import { IsString, IsNotEmpty, Length } from "class-validator";

export class VerifyTotpDto {
    @ApiProperty()
    @IsString()
    @IsNotEmpty()
    @Length(6, 6)
    code: string;
}

export class LoginVerifyTotpDto {
    @ApiProperty()
    @IsString()
    @IsNotEmpty()
    sessionToken: string;

    @ApiProperty()
    @IsString()
    @IsNotEmpty()
    code: string;
}

export class DisableTwoFactorDto {
    @ApiProperty()
    @IsString()
    @IsNotEmpty()
    password: string;
}

export class TwoFactorSetupResponseDto {
    @ApiProperty()
    qrCodeDataUrl: string;

    @ApiProperty()
    secret: string;

    @ApiProperty()
    otpauthUrl: string;
}

export class TwoFactorBackupCodesResponseDto {
    @ApiProperty({ type: [String] })
    backupCodes: string[];
}

export class TwoFactorStatusResponseDto {
    @ApiProperty()
    enabled: boolean;
}

export class LoginTwoFactorRequiredDto {
    @ApiProperty()
    requiresTwoFactor: boolean;

    @ApiProperty()
    sessionToken: string;
}
