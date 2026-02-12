import { useAuthStore } from "../stores/auth.store";
import {paths} from "#common/paths";

export default defineNuxtRouteMiddleware(() => {
    if (import.meta.server) return;

    const auth = useAuthStore();
    
    if (auth.isAuthenticated) return navigateTo(paths.home);
    if (localStorage.getItem('accessToken')) return navigateTo(paths.home);
});