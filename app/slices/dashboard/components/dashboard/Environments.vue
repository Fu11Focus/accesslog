<template>
  <div class="flex flex-col gap-3">
    <h3 class="text-lg font-semibold text-brand-text font-montserrat">{{ $t('home.credentialsByEnv') }}</h3>
    <Card class="bg-brand-darkest/60 border-brand-lighter/30 backdrop-blur-sm">
      <CardContent class="flex flex-col gap-3 p-4">
        <div v-for="env in items" :key="env.label" class="flex items-center justify-between">
          <Badge :class="env.color" variant="outline" class="text-[10px] px-1.5 py-0 border-current/30">
            {{ $t(`home.${env.label}`) }}
          </Badge>
          <div class="flex items-center gap-2">
            <div class="w-24 h-1.5 bg-brand-darkest rounded-full overflow-hidden">
              <div
                class="h-full rounded-full transition-all"
                :class="env.barColor"
                :style="{ width: `${total > 0 ? (env.count / total) * 100 : 0}%` }"
              />
            </div>
            <span class="text-base text-brand-text/50 w-6 text-right">{{ env.count }}</span>
          </div>
        </div>
      </CardContent>
    </Card>
  </div>
</template>

<script setup lang="ts">
import type { DashboardResponseDto } from '~~/slices/setup/api/data/repositories/api';

const props = defineProps<{
  environments: DashboardResponseDto['stats']['environments']
  total: number
}>();

const items = computed(() => [
  {
    label: 'development',
    count: props.environments.development ?? 0,
    color: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
    barColor: 'bg-emerald-500/20',
  },
  {
    label: 'staging',
    count: props.environments.staging ?? 0,
    color: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
    barColor: 'bg-amber-500/20',
  },
  {
    label: 'production',
    count: props.environments.production ?? 0,
    color: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    barColor: 'bg-blue-500/20',
  },
]);
</script>
