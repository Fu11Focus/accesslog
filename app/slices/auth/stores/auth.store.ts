import { defineStore } from "pinia";
import { AuthService, OpenAPI } from '../../setup/api/data/repositories/api';

export const useAuthStore = defineStore('auth', {
    state: () => ({
        user: null as any | null,
        accessToken: null as string | null,
        isAuthenticated: false,
        pendingTwoFactor: null as { sessionToken: string } | null,
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
            this.pendingTwoFactor = null;
            OpenAPI.TOKEN = undefined;
            localStorage.removeItem('accessToken');
        },

        async login(email: string, password: string) {
            const response: any = await AuthService.login({ email, password });

            if (response.requiresTwoFactor) {
                this.pendingTwoFactor = { sessionToken: response.sessionToken };
                return;
            }

            this.pendingTwoFactor = null;
            this.setTokens(response.accessToken);
            await this.fetchMe();
        },

        async verifyTwoFactor(code: string) {
            if (!this.pendingTwoFactor) throw new Error('No pending 2FA session');
            const response = await AuthService.verifyTwoFactorLogin({
                sessionToken: this.pendingTwoFactor.sessionToken,
                code,
            });
            this.pendingTwoFactor = null;
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
