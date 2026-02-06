import { ApiBearerAuth, ApiOperation, ApiTags } from "@nestjs/swagger";
import { AccessService } from "../data/access.service";
import { Body, Controller, Post, UseGuards } from "@nestjs/common";
import { AuthGuard } from "#users/auth/guards";
import { User } from "#users/auth/decorators";
import { CreateAccessDto } from "../dtos";
import { IAccess } from "../domain/interfaces";

@ApiBearerAuth()
@UseGuards(AuthGuard)
@Controller('access')
@ApiTags('Access')
export class AccessController {
    constructor(private readonly accessService: AccessService) { }

    @Post()
    @ApiOperation({
        description: 'Create access',
        operationId: 'createAccess',
    })
    async createAccess(@User() user, @Body() data: CreateAccessDto): Promise<IAccess> {
        return this.accessService.createAccess(data, user.encryptionKey);
    }
}