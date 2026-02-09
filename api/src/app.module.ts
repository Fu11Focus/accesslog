import { Module } from '@nestjs/common';
import { PrismaModule } from './slices/prisma/prisma.module';
import { UsersModule } from './slices/users/users/users.module';
import { AuthModule } from './slices/users/auth/auth.module';
import { ProjectsModule } from './slices/projects/projects/projects.module';
import { AccessModule } from './slices/projects/access/access.module';
import { TwoFactorModule } from './slices/projects/twoFactor/twoFactor.module';
import { RecoveryCodeModule } from './slices/projects/recoveryCodes/recoveryCode.module';
import { ActivityLogModule } from './slices/activityLog/activityLog.module';

@Module({
  imports: [PrismaModule, UsersModule, AuthModule, ProjectsModule, AccessModule, TwoFactorModule, RecoveryCodeModule, ActivityLogModule],
  controllers: [],
  providers: [],
})
export class AppModule { }
