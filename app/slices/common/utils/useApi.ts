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
        console.log('API Error:', error);
        console.log('Is ApiError:', error instanceof ApiError);
        
        if (error instanceof ApiError) {
            toast.error(error.body?.message || 'Something went wrong');
        } else {
            toast.error('No internet connection');
        }
        return null;
    }
}