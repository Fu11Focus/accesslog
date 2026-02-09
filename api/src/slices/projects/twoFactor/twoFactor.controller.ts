import { Body, Controller, Delete, Get, Param, Post, Put } from "@nestjs/common";
import { TwoFactorService } from "./domain/services/twoFactor.service";
import { UpdateTwoFactorDto } from "./dtos/update-two-factor.dto";
import { CreateTwoFactorDto } from "./dtos/create-two-factor.dto";
import { TwoFactorDto } from "./dtos/two-factor.dto";
import { AuthGuard } from "#users/auth/guards";
import { ApiBearerAuth, ApiTags } from "@nestjs/swagger";
import { UseGuards } from "@nestjs/common";

@ApiBearerAuth()
@UseGuards(AuthGuard)
@Controller('two-factor')
@ApiTags('two-factor')
export class TwoFactorController {
    constructor(private readonly twoFactorService: TwoFactorService) { }

    @Post()
    async createTwoFactor(@Body() data: CreateTwoFactorDto): Promise<TwoFactorDto> {
        return this.twoFactorService.createTwoFactor(data);
    }

    @Get('access/:accessId')
    async getTwoFactorByAccessId(@Param('accessId') accessId: string): Promise<TwoFactorDto> {
        return this.twoFactorService.getTwoFactorByAccessId(accessId);
    }

    @Get(':id')
    async getTwoFactorById(@Param('id') id: string): Promise<TwoFactorDto> {
        return this.twoFactorService.getTwoFactorById(id);
    }

    @Put(':id')
    async updateTwoFactor(@Param('id') id: string, @Body() data: UpdateTwoFactorDto): Promise<TwoFactorDto> {
        return this.twoFactorService.updateTwoFactor(id, data);
    }

    @Delete(':id')
    async deleteTwoFactorById(@Param('id') id: string): Promise<void> {
        return this.twoFactorService.deleteTwoFactorById(id);
    }
}