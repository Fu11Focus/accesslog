<script lang="ts" setup>
import { ArrowLeftIcon, FolderIcon } from 'lucide-vue-next';
import { paths } from '~~/slices/common/paths';
import { ProjectsService } from '~~/slices/setup/api/data/repositories/api';

const { t: $t } = useI18n();

const page = ref(1);
const limit = 12;
const statusFilter = ref('ALL');
const sortBy = ref('updatedAt');
const sortOrder = ref<'asc' | 'desc'>('desc');

const sortOptions = [
  { value: 'updatedAt', label: $t('filters.sortOptions.updatedAt') },
  { value: 'createdAt', label: $t('filters.sortOptions.createdAt') },
  { value: 'name', label: $t('filters.sortOptions.name') },
];

const { data: response, refresh } = await useAsyncData(
  'projects',
  () => ProjectsService.getAllProjects(
    page.value,
    limit,
    sortBy.value || undefined,
    sortOrder.value || undefined,
    statusFilter.value !== 'ALL' ? (statusFilter.value as 'ACTIVE' | 'ARCHIVED') : undefined,
  ),
  { server: false, default: () => ({ data: [], meta: { total: 0, page: 1, limit, totalPages: 0 } }) },
);

const projects = computed(() => response.value?.data ?? []);
const totalPages = computed(() => response.value?.meta?.totalPages ?? 0);

watch(page, () => refresh());
watch([statusFilter, sortBy, sortOrder], () => {
  page.value = 1;
  refresh();
});
</script>
<template>
  <div class="flex flex-col gap-6">
    <div class="flex items-center justify-between">
      <h2 class="text-2xl font-bold text-brand-text font-montserrat">{{ $t('projects.title') }}</h2>
      <div class="flex gap-4">
        <Button class="gap-2" @click="$router.push('/projects/create')">
        {{ $t('projects.create') }}
      </Button>
      <Button
      variant="ghost"
      class="gap-2"
      @click="$router.push(paths.home)">
        <ArrowLeftIcon :size="16" />
        {{ $t('back') }}
      </Button>
      </div>
    </div>

    <div class="flex items-center gap-3 flex-wrap">
      <Select v-model="statusFilter">
        <SelectTrigger class="w-40 py-2! text-sm">
          <SelectValue :placeholder="$t('filters.allStatuses')" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="ALL">{{ $t('filters.allStatuses') }}</SelectItem>
          <SelectItem value="ACTIVE">{{ $t('projects.status.active') }}</SelectItem>
          <SelectItem value="ARCHIVED">{{ $t('projects.status.archived') }}</SelectItem>
        </SelectContent>
      </Select>

      <Select v-model="sortBy">
        <SelectTrigger class="w-44 py-2! text-sm">
          <SelectValue :placeholder="$t('filters.sortBy')" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem v-for="opt in sortOptions" :key="opt.value" :value="opt.value">{{ opt.label }}</SelectItem>
        </SelectContent>
      </Select>

      <Select v-model="sortOrder">
        <SelectTrigger class="w-32 py-2! text-sm">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="desc">{{ $t('filters.desc') }}</SelectItem>
          <SelectItem value="asc">{{ $t('filters.asc') }}</SelectItem>
        </SelectContent>
      </Select>
    </div>

    <div v-if="projects.length === 0">
      <div class="flex flex-col items-center gap-4 mt-10">
        <FolderIcon :size="48" class="text-gray-400" />
        <p class="text-gray-500 text-2xl">{{ $t('projects.empty') }}</p>
      </div>
    </div>

    <template v-else>
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        <ProjectsThumb v-for="project in projects" :project="project" :key="project.id"/>
      </div>

      <Pagination
        v-if="totalPages > 1"
        v-slot="{ page: currentPage }"
        :total="response.meta.total"
        :items-per-page="limit"
        :sibling-count="1"
        :default-page="1"
        :page="page"
        @update:page="page = $event"
      >
        <PaginationContent v-slot="{ items }">
          <PaginationPrevious />
          <template v-for="(item, index) in items" :key="index">
            <PaginationItem v-if="item.type === 'page'" :value="item.value" :is-active="item.value === currentPage" />
            <PaginationEllipsis v-else :index="index" />
          </template>
          <PaginationNext />
        </PaginationContent>
      </Pagination>
    </template>
  </div>
</template>
