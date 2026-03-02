<template>
  <div class="flex flex-col gap-6">
    <div class="flex items-center justify-between">
      <h2 class="text-2xl font-bold text-brand-text font-montserrat">{{ route.params?.id ? $t('projects.edit') :
        $t('projects.create') }}</h2>
      <div class="flex gap-4">
        <Button @click="handleSubmit">
          {{ $t('projects.save') }}
        </Button>
        <Button variant="ghost" class="gap-2" @click="$router.push(paths.projects)">
          <ArrowLeftIcon :size="16" />
          {{ $t('back') }}
        </Button>
      </div>
    </div>
    <Card class="w-1/2">
      <CardContent class="flex flex-col gap-4 font-montserrat shadow-inner-brand-darkest/20">
        <form class="flex flex-col gap-5" @submit.prevent="handleSubmit">
          <FormField v-slot="{ componentField, errorMessage }" name="name">
            <Input v-bind="componentField" label="Project Name" placeholder="Enter project name" />
            <span v-if="errorMessage" class="text-red-400 text-base">{{ errorMessage }}</span>
          </FormField>
          <FormField v-slot="{ componentField, errorMessage }" name="clientName">
            <Input v-bind="componentField" label="Client Name" placeholder="Enter client name" />
            <span v-if="errorMessage" class="text-red-400 text-base">{{ errorMessage }}</span>
          </FormField>
          <FormField v-slot="{ componentField, errorMessage }" name="status">
            <Select v-bind="componentField" label="Status">
              <SelectTrigger class="w-full">
                <SelectValue :placeholder="$t('projects.projectStatus')" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="ACTIVE">{{ $t('projects.status.active') }}</SelectItem>
                <SelectItem value="ARCHIVED">{{ $t('projects.status.archived') }}</SelectItem>
              </SelectContent>
            </Select>
            <span v-if="errorMessage" class="text-red-400 text-base">{{ errorMessage }}</span>
          </FormField>
          <FormField v-slot="{ componentField, errorMessage }" name="description">
            <Textarea rows="5" v-bind="componentField" label="Description" placeholder="Enter project description" />
            <span v-if="errorMessage" class="text-red-400 text-base">{{ errorMessage }}</span>
          </FormField>
        </form>
      </CardContent>
    </Card>
  </div>
</template>

<script setup lang="ts">
import { ProjectsService, ProjectStatus, type CreateProjectDto } from '#setup/api/data/repositories/api';
import { z } from 'zod';
import { paths } from '#common/paths';
import { ArrowLeftIcon } from 'lucide-vue-next';
import { useSearchStore } from '#common/stores/search.store';
const route = useRoute();
const searchStore = useSearchStore();

const props = defineProps<{
  project?: CreateProjectDto
}>();

const formSchema = toTypedSchema(z.object({
  name: z.string().min(1, 'Project name is required'),
  clientName: z.string().optional(),
  status: z.nativeEnum(ProjectStatus),
  description: z.string().optional(),
}));

const form = useForm({
  validationSchema: formSchema,
  initialValues: {
    name: props.project?.name || '',
    clientName: props.project?.clientName || '',
    status: props.project?.status || ProjectStatus.ACTIVE,
    description: props.project?.description || '',
  },
});

const router = useRouter();

const handleSubmit = form.handleSubmit(async (values) => {
  if (route.params.id) {
    await apiCall(
      () => ProjectsService.updateProject(route.params.id as string, values),
      { successMessage: $t('projects.updatedSuccessfully') }
    );
  } else {
    const response = await apiCall(
      () => ProjectsService.createProject(values),
      { successMessage: $t('projects.createdSuccessfully') }
    );

    if (response?.id) {
      router.push({ path: paths.projectsEdit(response.id) });
    }
  }
  searchStore.invalidateCache();
});
</script>
