<script setup lang="ts">
import { UserIcon, SearchIcon, LogOutIcon } from 'lucide-vue-next';
import { useAuthStore } from '../../auth/stores/auth.store';
import { paths } from '#common/paths';
import { apiCall } from '../utils/useApi';

const auth = useAuthStore();

const handleLogout = async () => {
await apiCall(
    () => auth.logout()
)
navigateTo(paths.login);
}
</script>

<template>
    <header class="flex items-center justify-between max-w-200 mx-auto gap-40 px-5 py-2 border-2 border-brand-lighter rounded-4xl mt-5 shadow-inner-brand">
        <div class="flex items-center gap-2">
            <NuxtLink :to="paths.home">
                <h1 class="text-2xl font-bold font-oneday text-brand-text leading-none translate-y-0.5">AccessLog</h1>
            </NuxtLink>
        </div>
        <div class="flex gap-2">
            <Button>
                <SearchIcon class="text-brand-text"/>
            </Button>
            <DropdownMenu>
                <DropdownMenuTrigger as-child>
                    <Button>
                        <UserIcon class="text-brand-text"/>
                    </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent>
                    <DropdownMenuLabel class="flex gap-2 font-normal items-center">
                        <UserIcon :size="16"/>
                        {{ auth?.user?.email }}
                    </DropdownMenuLabel>
                    <DropdownMenuItem @select="handleLogout">
                        <LogOutIcon/>
                        {{ $t('auth.logOut') }}
                    </DropdownMenuItem>
                </DropdownMenuContent>
            </DropdownMenu>
        </div>
    </header>
</template>