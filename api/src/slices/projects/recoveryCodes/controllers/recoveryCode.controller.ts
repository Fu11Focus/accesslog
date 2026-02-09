import { Body, Controller, Delete, Get, Param, Patch, Post, UseGuards } from "@nestjs/common";
import { ApiBearerAuth, ApiOperation, ApiTags } from "@nestjs/swagger";
import { RecoveryCodeService } from "../domain/services/recoveryCode.service";
import { CreateRecoveryCodeDto } from "../dtos/create-recovery-code.dto";
import { User } from "#users/auth/decorators/user.decorator";
import { AuthGuard } from "#users/auth/guards";

@ApiBearerAuth()
@UseGuards(AuthGuard)
@Controller("recovery-code")
@ApiTags('recovery-code')
export class RecoveryCodeController {
    constructor(
        private readonly recoveryCodeService: RecoveryCodeService
    ) { }

    @Post()
    @ApiOperation({
        description: 'Create a recovery code',
        operationId: 'createRecoveryCode',
    })
    async createRecoveryCode(@User() user, @Body() data: CreateRecoveryCodeDto) {
        return this.recoveryCodeService.createRecoveryCode(data, user.encryptionKey);
    }

    @Get('two-factor/:twoFactorId')
    @ApiOperation({
        description: 'Get recovery codes by two factor id',
        operationId: 'getRecoveryCodeByTwoFactorId',
    })
    async getRecoveryCodeByTwoFactorId(@Param('twoFactorId') twoFactorId: string, @User() user) {
        return this.recoveryCodeService.getRecoveryCodesByTwoFactorId(twoFactorId, user.encryptionKey);
    }

    @Get(':id')
    @ApiOperation({
        description: 'Get a recovery code by id',
        operationId: 'getRecoveryCodeById',
    })
    async getRecoveryCodeById(@Param('id') id: string, @User() user) {
        return this.recoveryCodeService.getRecoveryCodeById(id, user.encryptionKey);
    }

    @Patch(':id/use')
    @ApiOperation({
        description: 'Use a recovery code',
        operationId: 'useRecoveryCode',
    })
    async useRecoveryCode(@Param('id') id: string, @User() user) {
        return this.recoveryCodeService.useRecoveryCode(id, user.encryptionKey, user.id);
    }

    @Delete(':id')
    @ApiOperation({
        description: 'Delete a recovery code',
        operationId: 'deleteRecoveryCode',
    })
    async deleteRecoveryCode(@Param('id') id: string) {
        return this.recoveryCodeService.deleteRecoveryCode(id);
    }
}
