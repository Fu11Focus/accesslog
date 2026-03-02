import { Body, Controller, Delete, Get, Param, Post, Put, UseGuards } from "@nestjs/common";
import { TwoFactorService } from "./domain/services/twoFactor.service";
import { UpdateTwoFactorDto } from "./dtos/update-two-factor.dto";
import { CreateTwoFactorDto } from "./dtos/create-two-factor.dto";
import { TwoFactorDto } from "./dtos/two-factor.dto";
import { AuthGuard } from "#users/auth/guards";
import { User } from "#users/auth/decorators";
import { ApiBearerAuth, ApiTags } from "@nestjs/swagger";

@ApiBearerAuth()
@UseGuards(AuthGuard)
@Controller('two-factor')
@ApiTags('two-factor')
export class TwoFactorController {
    constructor(private readonly twoFactorService: TwoFactorService) { }

    @Post()
    async createTwoFactor(@User() user, @Body() data: CreateTwoFactorDto): Promise<TwoFactorDto> {
        return this.twoFactorService.createTwoFactor(data, user.id);
    }

    @Get('access/:accessId')
    async getTwoFactorByAccessId(@User() user, @Param('accessId') accessId: string): Promise<TwoFactorDto> {
        return this.twoFactorService.getTwoFactorByAccessId(accessId, user.id);
    }

    @Get(':id')
    async getTwoFactorById(@User() user, @Param('id') id: string): Promise<TwoFactorDto> {
        return this.twoFactorService.getTwoFactorById(id, user.id);
    }

    @Put(':id')
    async updateTwoFactor(@User() user, @Param('id') id: string, @Body() data: UpdateTwoFactorDto): Promise<TwoFactorDto> {
        return this.twoFactorService.updateTwoFactor(id, data, user.id);
    }

    @Delete(':id')
    async deleteTwoFactorById(@User() user, @Param('id') id: string): Promise<void> {
        return this.twoFactorService.deleteTwoFactorById(id, user.id);
    }
}
