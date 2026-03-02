<script setup lang="ts">
import { ActivityLogService } from '#setup/api/data/repositories/api';
import { PlusIcon, PencilIcon, TrashIcon, EyeIcon, CopyIcon, KeyIcon, ShieldIcon, LoaderCircleIcon } from 'lucide-vue-next';

const props = defineProps<{ accessId: string }>();

const logs = ref<any[]>([]);
const loading = ref(true);

const actionConfig: Record<string, { icon: any; label: string; color: string }> = {
    ACCESS_CREATED: { icon: PlusIcon, label: 'activityLog.actions.created', color: 'text-emerald-400' },
    ACCESS_UPDATED: { icon: PencilIcon, label: 'activityLog.actions.updated', color: 'text-amber-400' },
    ACCESS_DELETED: { icon: TrashIcon, label: 'activityLog.actions.deleted', color: 'text-red-400' },
    ACCESS_VIEWED: { icon: EyeIcon, label: 'activityLog.actions.viewed', color: 'text-blue-400' },
    ACCESS_COPIED: { icon: CopyIcon, label: 'activityLog.actions.copied', color: 'text-purple-400' },
    PASSWORD_CHANGED: { icon: KeyIcon, label: 'activityLog.actions.passwordChanged', color: 'text-orange-400' },
    RECOVERY_CODE_USED: { icon: ShieldIcon, label: 'activityLog.actions.recoveryCodeUsed', color: 'text-rose-400' },
    RECOVERY_CODE_VIEWED: { icon: ShieldIcon, label: 'activityLog.actions.recoveryCodeViewed', color: 'text-cyan-400' },
};

function timeAgo(date: string) {
    const now = new Date();
    const past = new Date(date);
    const diff = Math.floor((now.getTime() - past.getTime()) / 1000);

    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    if (diff < 604800) return `${Math.floor(diff / 86400)}d ago`;
    return past.toLocaleDateString();
}

async function fetchLogs() {
    loading.value = true;
    try {
        logs.value = await ActivityLogService.getActivitiesByAccessId(props.accessId);
    } catch {
        logs.value = [];
    } finally {
        loading.value = false;
    }
}

onMounted(fetchLogs);
</script>

<template>
    <div class="space-y-2">
        <h4 class="text-brand-text/40 text-xs uppercase tracking-wider">{{ $t('activityLog.title') }}</h4>

        <div v-if="loading" class="flex items-center justify-center py-3">
            <LoaderCircleIcon :size="16" class="text-brand-lighter animate-spin" />
        </div>

        <p v-else-if="!logs.length" class="text-brand-text/30 text-sm">
            {{ $t('activityLog.empty') }}
        </p>

        <div v-else class="space-y-1">
            <div
                v-for="log in logs"
                :key="log.id"
                class="flex items-center gap-2 py-1 text-sm"
            >
                <component
                    :is="actionConfig[log.action]?.icon || PlusIcon"
                    :size="14"
                    :class="actionConfig[log.action]?.color || 'text-brand-text/50'"
                    class="shrink-0"
                />
                <span class="text-brand-text/70">
                    {{ $t(actionConfig[log.action]?.label || 'activityLog.actions.unknown') }}
                </span>
                <span class="text-brand-text/30 ml-auto text-xs shrink-0">
                    {{ timeAgo(log.createdAt) }}
                </span>
            </div>
        </div>
    </div>
</template>
