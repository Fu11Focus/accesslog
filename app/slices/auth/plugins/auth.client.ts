import { OpenAPI } from "../../setup/api/data/repositories/api";
import { useAuthStore } from "../stores/auth.store";

export default defineNuxtPlugin( {
    name: 'auth',
    dependsOn: ['api'],
    async setup() {
        const auth = useAuthStore();
        const token = localStorage.getItem('accessToken');
        if (!token) return;

        auth.setTokens(token);
        try {
            await auth.fetchMe();
        } catch {
            try {
                await auth.refreshToken();
                await auth.fetchMe();
            } catch {
                auth.clearSession();
            }
        }
    },
});