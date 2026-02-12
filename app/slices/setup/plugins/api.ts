import { OpenAPI } from '../api/data/repositories/api';

export default defineNuxtPlugin({
    name: 'api',
    setup() {
        const config = useRuntimeConfig();
        OpenAPI.BASE = config.public.apiBase as string;
        OpenAPI.WITH_CREDENTIALS = true;
    },
});
