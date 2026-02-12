import { defineStore } from "pinia";
import { AuthService, OpenAPI, UserDto } from '../../setup/api/data/repositories/api';

export const useAuthStore = defineStore('auth', {
    state: () => ({
        user: null as UserDto | null,
        accessToken: null as string | null,
        isAuthenticated: false,
    }),

    actions: {
        setTokens(accessToken: string) {
            this.accessToken = accessToken;
            OpenAPI.TOKEN = accessToken;
            localStorage.setItem('accessToken', accessToken);
        },
    
        clearSession() {
            this.accessToken = null;
            this.user = null;
            this.isAuthenticated = false;
            OpenAPI.TOKEN = undefined;
            localStorage.removeItem('accessToken');
        },
    
        async login(email: string, password: string) {
            const response = await AuthService.login({ email, password });
            this.setTokens(response.accessToken);
            await this.fetchMe();
        },
    
        async logout() {
            try { await AuthService.authControllerLogout(); } catch {}
            this.clearSession();
        },
    
        async logoutAll() {
            try { await AuthService.authControllerLogoutAll(); } catch {}
            this.clearSession();
        },
    
        async register(email: string, password: string) {
            await AuthService.register({ email, password });
            await this.login(email, password);  // auto-login
        },
    
        async refreshToken() {
            const response = await AuthService.refresh({});
            this.setTokens(response.accessToken);
        },
    
        async fetchMe() {
            const response = await AuthService.authControllerMe();
            this.user = response;
            this.isAuthenticated = true;
        },
    },
});
