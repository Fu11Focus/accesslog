<script setup lang="ts">
import { FolderIcon, KeyRoundIcon, LoaderCircleIcon } from 'lucide-vue-next';
import { paths } from '#common/paths';
import { useSearchStore } from '../../stores/search.store';

const open = defineModel<boolean>('open', { default: false });

const router = useRouter();
const searchStore = useSearchStore();
const { t } = useI18n();

watch(open, (isOpen) => {
    if (isOpen) {
        searchStore.fetchSearchData();
    }
});

onMounted(() => {
    const handler = (e: KeyboardEvent) => {
        if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
            e.preventDefault();
            open.value = !open.value;
        }
    };
    window.addEventListener('keydown', handler);
    onUnmounted(() => window.removeEventListener('keydown', handler));
});

function selectProject(id: string) {
    open.value = false;
    router.push(paths.projectsEdit(id));
}

function selectAccess(projectId: string) {
    open.value = false;
    router.push({ path: paths.projectsEdit(projectId), query: { tab: 'access' } });
}

function envBadgeClass(env: string) {
    switch (env.toUpperCase()) {
        case 'PRODUCTION': return 'bg-red-500/20 text-red-400 border-red-500/30';
        case 'STAGING': return 'bg-amber-500/20 text-amber-400 border-amber-500/30';
        case 'DEVELOPMENT': return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30';
        default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    }
}
</script>

<template>
    <CommandDialog v-model:open="open" :title="t('search.placeholder')" :description="t('search.placeholder')">
        <CommandInput :placeholder="t('search.placeholder')" />
        <CommandList>
            <!-- Loading -->
            <div v-if="searchStore.loading && !searchStore.lastFetchedAt" class="flex items-center justify-center py-6">
                <LoaderCircleIcon :size="20" class="text-brand-lighter animate-spin" />
                <span class="ml-2 text-brand-text/50 text-sm">{{ t('search.loading') }}</span>
            </div>

            <CommandEmpty>{{ t('search.empty') }}</CommandEmpty>

            <!-- Projects -->
            <CommandGroup v-if="searchStore.projects.length" :heading="t('search.groups.projects')">
                <CommandItem
                    v-for="project in searchStore.projects"
                    :key="project.id"
                    :value="`project-${project.id}-${project.name}`"
                    class="flex items-center gap-2"
                    @select="selectProject(project.id)"
                >
                    <FolderIcon :size="16" class="text-brand-lighter shrink-0" />
                    <div class="flex flex-col flex-1 min-w-0">
                        <span class="text-brand-text text-sm">{{ project.name }}</span>
                        <span v-if="project.clientName" class="text-brand-text/40 text-xs">{{ project.clientName }}</span>
                    </div>
                    <Badge
                        :class="project.status === 'ACTIVE'
                            ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
                            : 'bg-gray-500/20 text-gray-400 border-gray-500/30'"
                        variant="outline"
                        class="text-[10px] px-1.5 py-0 shrink-0"
                    >
                        {{ project.status.toLowerCase() }}
                    </Badge>
                    <!-- Hidden searchable text -->
                    <span class="sr-only">{{ project.description }} {{ project.clientName }}</span>
                </CommandItem>
            </CommandGroup>

            <CommandSeparator v-if="searchStore.projects.length && searchStore.accesses.length" />

            <!-- Access Credentials -->
            <CommandGroup v-if="searchStore.accesses.length" :heading="t('search.groups.access')">
                <CommandItem
                    v-for="access in searchStore.accesses"
                    :key="access.id"
                    :value="`access-${access.id}-${access.serviceName}`"
                    class="flex items-center gap-2"
                    @select="selectAccess(access.projectId)"
                >
                    <KeyRoundIcon :size="16" class="text-brand-lighter shrink-0" />
                    <div class="flex flex-col flex-1 min-w-0">
                        <span class="text-brand-text text-sm">{{ access.serviceName }}</span>
                        <span class="text-brand-text/40 text-xs truncate">{{ access.projectName }} &middot; {{ access.serviceUrl }}</span>
                    </div>
                    <Badge
                        :class="envBadgeClass(access.environment)"
                        variant="outline"
                        class="text-[10px] px-1.5 py-0 shrink-0"
                    >
                        {{ access.environment.toLowerCase() }}
                    </Badge>
                    <!-- Hidden searchable text -->
                    <span class="sr-only">{{ access.notes }} {{ access.serviceUrl }} {{ access.projectName }}</span>
                </CommandItem>
            </CommandGroup>
        </CommandList>
    </CommandDialog>
</template>
