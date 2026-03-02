<template>
  <DashboardSkeleton v-if="loading" />

  <div v-else-if="data" class="flex flex-col gap-6">
    <!-- Welcome -->
    <div class="flex items-center justify-between">
      <div>
        <ClientOnly>
          <h2 class="text-2xl font-bold text-brand-text font-montserrat">
            {{ $t('home.welcome') }},
            <span class="text-brand-lighter">{{ auth.user?.email?.split('@')[0] }}</span>
          </h2>
          <template #fallback>
            <h2 class="text-2xl font-bold text-brand-text font-montserrat">
              {{ $t('home.welcome') }}
            </h2>
          </template>
        </ClientOnly>
        <p class="text-brand-text/40 text-base mt-1">{{ $t('home.overview') }}</p>
      </div>
      <div class="flex gap-2">
        <Button class="gap-2" @click="navigateTo(paths.projects)">
          {{ $t('projects.create') }}
        </Button>
      </div>
    </div>

    <!-- Stats -->
    <DashboardStats :stats="data.stats" />

    <!-- Content Grid -->
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
      <DashboardProjects :projects="data.recentProjects" />

      <div class="flex flex-col gap-6">
        <DashboardEnvironments
          :environments="data.stats.environments"
          :total="data.stats.totalCredentials"
        />
        <DashboardActivity :activities="data.recentActivities" />
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { paths } from '#common/paths';
import { useAuthStore } from '~~/slices/auth/stores/auth.store';
import { DashboardService, type DashboardResponseDto } from '~~/slices/setup/api/data/repositories/api';
import { apiCall } from '#common/utils/useApi';
import DashboardSkeleton from './Skeleton.vue';
import DashboardStats from './Stats.vue';
import DashboardProjects from './Projects.vue';
import DashboardEnvironments from './Environments.vue';
import DashboardActivity from './Activity.vue';

const auth = useAuthStore();
const data = ref<DashboardResponseDto | null>(null);
const loading = ref(true);

onMounted(async () => {
  data.value = await apiCall(() => DashboardService.getDashboardData());
  loading.value = false;
});
</script>
