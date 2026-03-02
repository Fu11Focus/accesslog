<template>
  <div v-if="project" class="flex flex-col gap-6">
    <div class="flex gap-4 border-b border-brand-lighter/20 pb-1">
      <button
        v-for="tab in tabs" :key="tab.key"
        class="px-4 py-2 text-base font-montserrat transition-colors"
        :class="activeTab === tab.key
          ? 'text-brand-text border-b-2 border-brand-lighter'
          : 'text-brand-text/40 hover:text-brand-text/70'"
        @click="activeTab = tab.key"
      >
        {{ tab.label }}
      </button>
    </div>

    <ProjectsForm v-if="activeTab === 'details'" :project="project" />
    <AccessProvider v-if="activeTab === 'access'" :project-id="(route.params.id as string)" />
  </div>
</template>

<script setup lang="ts">
import { ProjectsService } from '#setup/api/data/repositories/api';

definePageMeta({ middleware: ['auth'] });

const route = useRoute();
const { t } = useI18n();

const activeTab = ref((route.query.tab as string) || 'details');

const tabs = computed(() => [
  { key: 'details', label: t('projects.tabs.details') },
  { key: 'access', label: t('projects.tabs.access') },
]);

const { data: project } = await useAsyncData(
  'project',
  () => ProjectsService.getProject(route.params.id as string),
  { server: false },
);

watch(project, (p) => {
  if (p?.name) route.meta.projectName = p.name;
}, { immediate: true });
</script>
