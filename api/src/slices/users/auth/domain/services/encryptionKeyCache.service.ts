import { Injectable, Inject } from '@nestjs/common';
import { CACHE_MANAGER, Cache } from '@nestjs/cache-manager';

@Injectable()
export class EncryptionKeyCacheService {
    private readonly KEY_PREFIX = 'encryption:';
    private readonly DEFAULT_TTL = 7 * 24 * 60 * 60; // 7 days

    constructor(@Inject(CACHE_MANAGER) private cacheManager: Cache) { }

    async set(userId: string, encryptionKey: string): Promise<void> {
        const key = this.KEY_PREFIX + userId;
        await this.cacheManager.set(key, encryptionKey, this.DEFAULT_TTL);
    }

    async get(userId: string): Promise<string | null> {
        const key = this.KEY_PREFIX + userId;
        const value = await this.cacheManager.get<string>(key);
        return value || null;
    }

    async refresh(userId: string): Promise<boolean> {
        const key = this.KEY_PREFIX + userId;
        const value = await this.cacheManager.get<string>(key);

        if (value) {
            await this.cacheManager.set(key, value, this.DEFAULT_TTL);
            return true;
        }
        return false;
    }

    async delete(userId: string): Promise<void> {
        const key = this.KEY_PREFIX + userId;
        await this.cacheManager.del(key);
    }

    async exists(userId: string): Promise<boolean> {
        const value = await this.get(userId);
        return value !== null;
    }
}