<template>
  <div class="flex flex-col gap-3">
    <h3 class="text-lg font-semibold text-brand-text font-montserrat">{{ $t('home.recentActivity') }}</h3>
    <Card class="bg-brand-darkest/60 border-brand-lighter/30 backdrop-blur-sm">
      <CardContent class="flex flex-col p-4">
        <template v-if="activities.length">
          <div
            v-for="(activity, index) in activities"
            :key="activity.id"
            class="flex items-start gap-3 py-2.5"
            :class="{ 'border-t border-brand-lighter/10': index > 0 }"
          >
            <div class="mt-0.5">
              <component
                :is="actionIcons[activity.action] ?? ActivityIcon"
                :size="14"
                :class="actionColors[activity.action] ?? 'text-brand-text/40'"
              />
            </div>
            <div class="flex-1 min-w-0">
              <p class="text-base text-brand-text/70 truncate">
                <span class="capitalize">{{ formatAction(activity.action) }}</span>
              </p>
              <p class="text-[10px] text-brand-text/40 truncate">
                {{ activity.serviceName }} &middot; {{ activity.projectName }}
              </p>
            </div>
            <ClientOnly>
              <span class="text-[10px] text-brand-text/30 whitespace-nowrap">{{ timeAgo(activity.createdAt) }}</span>
              <template #fallback><span class="text-[10px] text-brand-text/30">—</span></template>
            </ClientOnly>
          </div>
        </template>
        <p v-else class="text-center text-brand-text/40">{{ $t('home.noActivity') }}</p>
      </CardContent>
    </Card>
  </div>
</template>

<script setup lang="ts">
import {
  PlusIcon, PencilIcon, TrashIcon, EyeIcon,
  CopyIcon, KeyIcon, ShieldCheckIcon, ActivityIcon,
} from 'lucide-vue-next';
import type { DashboardResponseDto } from '~~/slices/setup/api/data/repositories/api';

defineProps<{
  activities: DashboardResponseDto['recentActivities']
}>();

const actionIcons: Record<string, any> = {
  ACCESS_CREATED: PlusIcon,
  ACCESS_UPDATED: PencilIcon,
  ACCESS_DELETED: TrashIcon,
  ACCESS_VIEWED: EyeIcon,
  ACCESS_COPIED: CopyIcon,
  PASSWORD_CHANGED: KeyIcon,
  RECOVERY_CODE_USED: ShieldCheckIcon,
  RECOVERY_CODE_VIEWED: EyeIcon,
};

const actionColors: Record<string, string> = {
  ACCESS_CREATED: 'text-emerald-400',
  ACCESS_UPDATED: 'text-amber-400',
  ACCESS_DELETED: 'text-red-400',
  ACCESS_VIEWED: 'text-blue-400',
  ACCESS_COPIED: 'text-brand-text/60',
  PASSWORD_CHANGED: 'text-purple-400',
  RECOVERY_CODE_USED: 'text-orange-400',
  RECOVERY_CODE_VIEWED: 'text-blue-400',
};

function formatAction(action: string) {
  return action.replace(/_/g, ' ').toLowerCase();
}

function timeAgo(date: string) {
  const now = new Date();
  const past = new Date(date);
  const diffMs = now.getTime() - past.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);

  if (diffMins < 1) return 'just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  return `${diffDays}d ago`;
}
</script>
