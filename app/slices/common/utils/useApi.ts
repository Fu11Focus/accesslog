import { toast } from 'vue-sonner'
import { ApiError } from '#setup/api/data/repositories/api/core/ApiError';

export async function apiCall<T>(
    fn: () => Promise<T>,
    options?: { successMessage?: string }
): Promise<T | null> {
    try {
        const result = await fn();
        if (options?.successMessage) {
            toast.success(options.successMessage);
        }
        return result;
    } catch (error) {
        if (error instanceof ApiError) {
            toast.error(error.body?.message || 'Something went wrong');
        } else {
            toast.error('No internet connection');
        }
        return null;
    }
}