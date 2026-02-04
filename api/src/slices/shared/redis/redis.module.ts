import { Module } from '@nestjs/common';
import { CacheModule } from '@nestjs/cache-manager';
import { redisStore } from 'cache-manager-redis-store';

@Module({
    imports: [
        CacheModule.registerAsync({
            isGlobal: true,
            useFactory: async () => ({
                store: await redisStore({
                    socket: {
                        host: process.env.REDIS_HOST || 'localhost',
                        port: parseInt(process.env.REDIS_PORT || '6379'),
                    },
                    password: process.env.REDIS_PASSWORD || undefined,
                    ttl: parseInt(process.env.REDIS_TTL || '604800'), // 7 days
                }),
            }),
        }),
    ],
})
export class RedisModule { }