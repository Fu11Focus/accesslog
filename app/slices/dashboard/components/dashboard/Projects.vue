<template>
  <div class="lg:col-span-2 flex flex-col gap-4">
    <div class="flex items-center justify-between">
      <h3 class="text-lg font-semibold text-brand-text font-montserrat">{{ $t('home.recentProjects') }}</h3>
      <NuxtLink :to="paths.projects" class="flex items-center gap-1 text-base text-brand-lighter hover:text-brand-text transition-colors">
        {{ $t('home.viewAll') }}
        <ArrowRightIcon :size="14" />
      </NuxtLink>
    </div>

    <div v-if="projects.length" class="grid grid-cols-1 md:grid-cols-2 gap-4">
      <Card
        v-for="project in projects"
        :key="project.id"
        class="bg-brand-darkest/60 border-brand-lighter/30 backdrop-blur-sm hover:border-brand-lighter/60 transition-colors cursor-pointer"
        @click="navigateTo(paths.projectsEdit(project.id))"
      >
        <CardContent class="flex flex-col gap-3 p-4">
          <div class="flex items-center justify-between">
            <span class="text-base font-medium text-brand-text">{{ project.name }}</span>
            <Badge
              :class="project.status === 'ACTIVE'
                ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
                : 'bg-gray-500/20 text-gray-400 border-gray-500/30'"
              variant="outline"
              class="text-[10px] px-1.5 py-0"
            >
              {{ project.status.toLowerCase() }}
            </Badge>
          </div>
          <div class="flex items-center justify-between text-base text-brand-text/40">
            <span>{{ project.clientName }}</span>
            <div class="flex items-center gap-1">
              <KeyRoundIcon :size="10" />
              <span>{{ project.credentialsCount }}</span>
            </div>
          </div>
          <div class="text-[10px] text-brand-text/30">
            <ClientOnly>
              Updated {{ formatDate(project.updatedAt) }}
              <template #fallback>Updated —</template>
            </ClientOnly>
          </div>
        </CardContent>
      </Card>
    </div>

    <Card v-else class="bg-brand-darkest/60 border-brand-lighter/30 backdrop-blur-sm">
      <CardContent class="p-6 text-center text-brand-text/40">
        {{ $t('home.noProjects') }}
      </CardContent>
    </Card>
  </div>
</template>

<script setup lang="ts">
import { ArrowRightIcon, KeyRoundIcon } from 'lucide-vue-next';
import { paths } from '#common/paths';
import type { DashboardResponseDto } from '~~/slices/setup/api/data/repositories/api';

defineProps<{
  projects: DashboardResponseDto['recentProjects']
}>();

function formatDate(date: string) {
  return new Date(date).toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
  });
}
</script>
