import { useAuthStore } from "../stores/auth.store";
import {paths} from "#common/paths";

export default defineNuxtRouteMiddleware(() => {
    if (import.meta.server) return; // пропускаємо на сервері

    const auth = useAuthStore();
    
    if (auth.isAuthenticated) return;
    if (localStorage.getItem('accessToken')) return;
    
    return navigateTo(paths.login);
});