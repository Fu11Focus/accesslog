<template>
  <div class="grid grid-cols-2 lg:grid-cols-4 gap-4">
    <Card v-for="stat in items" :key="stat.label" class="bg-brand-darkest/60 border-brand-lighter/30 backdrop-blur-sm">
      <CardContent class="flex items-center gap-3 p-4">
        <div class="p-2 rounded-lg" :class="stat.iconBg">
          <component :is="stat.icon" :size="20" :class="stat.iconColor" />
        </div>
        <div>
          <p class="text-2xl font-bold text-brand-text">{{ stat.value }}</p>
          <p class="text-base text-brand-text/40">{{ $t(stat.label) }}</p>
        </div>
      </CardContent>
    </Card>
  </div>
</template>

<script setup lang="ts">
import { FolderIcon, KeyRoundIcon, ServerIcon, ActivityIcon } from 'lucide-vue-next';
import type { DashboardResponseDto } from '~~/slices/setup/api/data/repositories/api';

const props = defineProps<{
  stats: DashboardResponseDto['stats']
}>();

const items = computed(() => [
  {
    icon: FolderIcon,
    iconBg: 'bg-brand-lighter/20',
    iconColor: 'text-brand-lighter',
    value: props.stats.totalProjects,
    label: 'home.totalProjects',
  },
  {
    icon: KeyRoundIcon,
    iconBg: 'bg-emerald-500/20',
    iconColor: 'text-emerald-400',
    value: props.stats.totalCredentials,
    label: 'home.totalCredentials',
  },
  {
    icon: ServerIcon,
    iconBg: 'bg-amber-500/20',
    iconColor: 'text-amber-400',
    value: (props.stats.environments.production ?? 0) + (props.stats.environments.staging ?? 0) + (props.stats.environments.development ?? 0),
    label: 'home.activeEnvironments',
  },
  {
    icon: ActivityIcon,
    iconBg: 'bg-blue-500/20',
    iconColor: 'text-blue-400',
    value: props.stats.activities,
    label: 'home.recentActivities',
  },
]);
</script>
