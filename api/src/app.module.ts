import { Module } from '@nestjs/common';
import { PrismaModule } from './slices/prisma/prisma.module';
import { UsersModule } from './slices/users/users/users.module';
import { AuthModule } from './slices/users/auth/auth.module';

@Module({
  imports: [PrismaModule, UsersModule, AuthModule],
  controllers: [],
  providers: [],
})
export class AppModule { }
