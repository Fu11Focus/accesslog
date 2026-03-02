<template>
  <Card class="border-brand-lighter/20">
    <CardContent class="flex flex-col gap-4 font-montserrat">
      <form class="flex flex-col gap-4" @submit.prevent="handleSubmit">
        <div class="grid grid-cols-2 gap-4">
          <FormField v-slot="{ componentField, errorMessage }" name="serviceName">
            <Input v-bind="componentField" :label="$t('access.fields.serviceName')" placeholder="e.g. AWS Console" />
            <span v-if="errorMessage" class="text-red-400 text-base">{{ errorMessage }}</span>
          </FormField>
          <FormField v-slot="{ componentField, errorMessage }" name="serviceUrl">
            <Input v-bind="componentField" :label="$t('access.fields.serviceUrl')" placeholder="https://..." />
            <span v-if="errorMessage" class="text-red-400 text-base">{{ errorMessage }}</span>
          </FormField>
        </div>

        <div class="grid grid-cols-2 gap-4">
          <FormField v-slot="{ componentField, errorMessage }" name="environment">
            <Select v-bind="componentField">
              <SelectTrigger class="w-full">
                <SelectValue :placeholder="$t('access.fields.environment')" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="PRODUCTION">{{ $t('access.environment.production') }}</SelectItem>
                <SelectItem value="STAGING">{{ $t('access.environment.staging') }}</SelectItem>
                <SelectItem value="DEVELOPMENT">{{ $t('access.environment.development') }}</SelectItem>
              </SelectContent>
            </Select>
            <span v-if="errorMessage" class="text-red-400 text-base">{{ errorMessage }}</span>
          </FormField>
          <FormField v-slot="{ componentField, errorMessage }" name="accessLevel">
            <Select v-bind="componentField">
              <SelectTrigger class="w-full">
                <SelectValue :placeholder="$t('access.fields.accessLevel')" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="ADMIN">{{ $t('access.level.admin') }}</SelectItem>
                <SelectItem value="EDITOR">{{ $t('access.level.editor') }}</SelectItem>
                <SelectItem value="VIEWER">{{ $t('access.level.viewer') }}</SelectItem>
              </SelectContent>
            </Select>
            <span v-if="errorMessage" class="text-red-400 text-base">{{ errorMessage }}</span>
          </FormField>
        </div>

        <div class="grid grid-cols-2 gap-4">
          <FormField v-slot="{ componentField, errorMessage }" name="login">
            <Input v-bind="componentField" :label="$t('access.fields.login')" placeholder="username or email" />
            <span v-if="errorMessage" class="text-red-400 text-base">{{ errorMessage }}</span>
          </FormField>
          <FormField v-slot="{ componentField, errorMessage }" name="password">
            <Input v-bind="componentField" :label="$t('access.fields.password')" type="password" placeholder="********" />
            <span v-if="errorMessage" class="text-red-400 text-base">{{ errorMessage }}</span>
          </FormField>
        </div>

        <div class="grid grid-cols-2 gap-4">
          <FormField v-slot="{ componentField, errorMessage }" name="owner">
            <Input v-bind="componentField" :label="$t('access.fields.owner')" placeholder="Who owns this access?" />
            <span v-if="errorMessage" class="text-red-400 text-base">{{ errorMessage }}</span>
          </FormField>
        </div>

        <FormField v-slot="{ componentField, errorMessage }" name="notes">
          <Textarea v-bind="componentField" rows="3" :label="$t('access.fields.notes')" placeholder="Additional notes..." />
          <span v-if="errorMessage" class="text-red-400 text-base">{{ errorMessage }}</span>
        </FormField>

        <div class="flex gap-3 justify-end">
          <Button type="button" variant="ghost" @click="$emit('cancel')">
            {{ $t('access.cancel') }}
          </Button>
          <Button type="submit">
            {{ $t('access.save') }}
          </Button>
        </div>
      </form>
    </CardContent>
  </Card>
</template>

<script setup lang="ts">
import { AccessService } from '#setup/api/data/repositories/api';
import { z } from 'zod';

const props = defineProps<{
  projectId: string
  access?: {
    id: string
    serviceName?: string
    serviceUrl?: string
    environment: string
    accessLevel: string
    login: string
    password?: string
    notes?: string
    owner?: string
  }
}>();

const emit = defineEmits<{
  saved: []
  cancel: []
}>();

const { t: $t } = useI18n();

const formSchema = toTypedSchema(z.object({
  serviceName: z.string().optional(),
  serviceUrl: z.string().optional(),
  environment: z.enum(['PRODUCTION', 'STAGING', 'DEVELOPMENT']),
  accessLevel: z.enum(['ADMIN', 'EDITOR', 'VIEWER']),
  login: z.string().min(1, 'Login is required'),
  password: z.string().min(1, 'Password is required'),
  notes: z.string().optional(),
  owner: z.string().optional(),
}));

const form = useForm({
  validationSchema: formSchema,
  initialValues: {
    serviceName: props.access?.serviceName ?? '',
    serviceUrl: props.access?.serviceUrl ?? '',
    environment: props.access?.environment ?? 'PRODUCTION',
    accessLevel: props.access?.accessLevel ?? 'ADMIN',
    login: props.access?.login ?? '',
    password: props.access?.password ?? '',
    notes: props.access?.notes ?? '',
    owner: props.access?.owner ?? '',
  },
});

const handleSubmit = form.handleSubmit(async (values) => {
  if (props.access?.id) {
    await apiCall(
      () => AccessService.updateAccessById({ id: props.access!.id, ...values }),
      { successMessage: $t('access.updatedSuccessfully') },
    );
  } else {
    await apiCall(
      () => AccessService.createAccess({ projectId: props.projectId, ...values }),
      { successMessage: $t('access.createdSuccessfully') },
    );
  }
  emit('saved');
});
</script>
