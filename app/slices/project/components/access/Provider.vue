<template>
  <div class="flex flex-col gap-4">
    <div class="flex items-center justify-between">
      <h3 class="text-lg font-semibold text-brand-text font-montserrat">{{ $t('access.title') }}</h3>
      <Button v-if="!showForm" class="gap-2" @click="showForm = true">
        {{ $t('access.create') }}
      </Button>
    </div>

    <AccessForm
      v-if="showForm"
      :project-id="projectId"
      @saved="onSaved"
      @cancel="showForm = false"
    />

    <div class="flex items-center gap-3 flex-wrap">
      <Select v-model="environmentFilter">
        <SelectTrigger class="w-44 py-2! text-sm">
          <SelectValue :placeholder="$t('filters.allEnvironments')" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="ALL">{{ $t('filters.allEnvironments') }}</SelectItem>
          <SelectItem value="PRODUCTION">{{ $t('access.environment.production') }}</SelectItem>
          <SelectItem value="STAGING">{{ $t('access.environment.staging') }}</SelectItem>
          <SelectItem value="DEVELOPMENT">{{ $t('access.environment.development') }}</SelectItem>
        </SelectContent>
      </Select>

      <Select v-model="accessLevelFilter">
        <SelectTrigger class="w-36 py-2! text-sm">
          <SelectValue :placeholder="$t('filters.allLevels')" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="ALL">{{ $t('filters.allLevels') }}</SelectItem>
          <SelectItem value="ADMIN">{{ $t('access.level.admin') }}</SelectItem>
          <SelectItem value="EDITOR">{{ $t('access.level.editor') }}</SelectItem>
          <SelectItem value="VIEWER">{{ $t('access.level.viewer') }}</SelectItem>
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

    <div v-if="!accesses?.length && !showForm" class="flex flex-col items-center gap-4 mt-10">
      <KeyIcon :size="48" class="text-gray-400" />
      <p class="text-gray-500 text-2xl">{{ $t('access.empty') }}</p>
    </div>

    <template v-else>
      <div class="flex flex-col gap-3">
        <template v-for="access in accesses" :key="access.id">
          <AccessForm
            v-if="editingId === access.id"
            :project-id="projectId"
            :access="access"
            @saved="onSaved"
            @cancel="editingId = null"
          />
          <AccessThumb
            v-else
            :access="access"
            @edit="editingId = access.id"
            @delete="handleDelete(access.id)"
          />
        </template>
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

<script setup lang="ts">
import { KeyIcon } from 'lucide-vue-next';
import { AccessService } from '#setup/api/data/repositories/api';
import { useSearchStore } from '#common/stores/search.store';

const props = defineProps<{
  projectId: string
}>();

const { t: $t } = useI18n();
const searchStore = useSearchStore();
const showForm = ref(false);
const editingId = ref<string | null>(null);
const page = ref(1);
const limit = 10;
const environmentFilter = ref('ALL');
const accessLevelFilter = ref('ALL');
const sortBy = ref('createdAt');
const sortOrder = ref<'asc' | 'desc'>('desc');

const sortOptions = [
  { value: 'createdAt', label: $t('filters.sortOptions.createdAt') },
  { value: 'serviceName', label: $t('filters.sortOptions.serviceName') },
];

const { data: response, refresh } = await useAsyncData(
  `access-${props.projectId}`,
  () => AccessService.getAccessByProjectId(
    props.projectId,
    page.value,
    limit,
    sortBy.value || undefined,
    sortOrder.value || undefined,
    environmentFilter.value !== 'ALL' ? (environmentFilter.value as 'PRODUCTION' | 'STAGING' | 'DEVELOPMENT') : undefined,
    accessLevelFilter.value !== 'ALL' ? (accessLevelFilter.value as 'ADMIN' | 'EDITOR' | 'VIEWER') : undefined,
  ),
  { server: false, default: () => ({ data: [], meta: { total: 0, page: 1, limit, totalPages: 0 } }) },
);

const accesses = computed(() => response.value?.data ?? []);
const totalPages = computed(() => response.value?.meta?.totalPages ?? 0);

watch(page, () => refresh());
watch([environmentFilter, accessLevelFilter, sortBy, sortOrder], () => {
  page.value = 1;
  refresh();
});

async function onSaved() {
  showForm.value = false;
  editingId.value = null;
  await refresh();
  searchStore.invalidateCache();
}

async function handleDelete(id: string) {
  await apiCall(
    () => AccessService.deleteAccessById(id),
    { successMessage: $t('access.deletedSuccessfully') },
  );
  await refresh();
  searchStore.invalidateCache();
}
</script>
