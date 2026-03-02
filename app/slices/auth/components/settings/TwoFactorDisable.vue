<template>
  <Card>
    <CardHeader>
      <div class="flex items-center gap-3">
        <CardTitle>{{ $t('settings.twoFactor.title') }}</CardTitle>
        <Badge variant="outline" class="text-green-400 border-green-400/30">
          {{ $t('settings.twoFactor.enabled') }}
        </Badge>
      </div>
      <CardDescription>{{ $t('settings.twoFactor.enabledDescription') }}</CardDescription>
    </CardHeader>
    <CardContent class="flex flex-col gap-4">
      <!-- Regenerate backup codes -->
      <Dialog v-model:open="showRegenerate">
        <DialogTrigger as-child>
          <Button variant="outline">{{ $t('settings.twoFactor.regenerateBackupCodes') }}</Button>
        </DialogTrigger>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{{ $t('settings.twoFactor.regenerateBackupCodes') }}</DialogTitle>
            <DialogDescription>{{ $t('settings.twoFactor.regenerateDescription') }}</DialogDescription>
          </DialogHeader>

          <div v-if="!regeneratedCodes">
            <form class="flex flex-col gap-4" @submit.prevent="onRegenerate">
              <FormField v-slot="{ componentField }" name="code">
                <FormItem>
                  <FormLabel>{{ $t('settings.twoFactor.enterCode') }}</FormLabel>
                  <FormControl>
                    <Input
                      v-bind="componentField"
                      type="text"
                      inputmode="numeric"
                      autocomplete="one-time-code"
                      maxlength="6"
                      :placeholder="$t('settings.twoFactor.codePlaceholder')"
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              </FormField>
              <Button type="submit" :disabled="loading">{{ $t('settings.twoFactor.regenerate') }}</Button>
            </form>
          </div>

          <div v-else class="flex flex-col gap-4">
            <div class="grid grid-cols-2 gap-2 p-4 bg-brand-darkest rounded-lg">
              <code v-for="code in regeneratedCodes" :key="code" class="text-sm text-brand-text font-mono text-center py-1">
                {{ code }}
              </code>
            </div>
            <p class="text-xs text-yellow-400">{{ $t('settings.twoFactor.backupCodesWarning') }}</p>
            <DialogClose as-child>
              <Button @click="regeneratedCodes = null">{{ $t('settings.twoFactor.done') }}</Button>
            </DialogClose>
          </div>
        </DialogContent>
      </Dialog>

      <!-- Disable 2FA -->
      <Dialog v-model:open="showDisable">
        <DialogTrigger as-child>
          <Button variant="destructive">{{ $t('settings.twoFactor.disable') }}</Button>
        </DialogTrigger>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{{ $t('settings.twoFactor.disableTitle') }}</DialogTitle>
            <DialogDescription>{{ $t('settings.twoFactor.disableDescription') }}</DialogDescription>
          </DialogHeader>
          <form class="flex flex-col gap-4" @submit.prevent="onDisable">
            <FormField v-slot="{ componentField }" name="password">
              <FormItem>
                <FormLabel>{{ $t('settings.twoFactor.confirmPassword') }}</FormLabel>
                <FormControl>
                  <Input type="password" v-bind="componentField" />
                </FormControl>
                <FormMessage />
              </FormItem>
            </FormField>
            <Button type="submit" variant="destructive" :disabled="loading">
              {{ $t('settings.twoFactor.confirmDisable') }}
            </Button>
          </form>
        </DialogContent>
      </Dialog>
    </CardContent>
  </Card>
</template>

<script setup lang="ts">
import { z } from 'zod';
import { toTypedSchema } from '@vee-validate/zod';
import { useForm } from 'vee-validate';
import { AuthService } from '#setup/api/data/repositories/api';
import { apiCall } from '#common/utils/useApi';

const emit = defineEmits<{ disabled: [] }>();

const loading = ref(false);
const showRegenerate = ref(false);
const showDisable = ref(false);
const regeneratedCodes = ref<string[] | null>(null);

const regenerateSchema = toTypedSchema(z.object({
  code: z.string().length(6),
}));
const disableSchema = toTypedSchema(z.object({
  password: z.string().min(6),
}));

const regenerateForm = useForm({ validationSchema: regenerateSchema });
const disableForm = useForm({ validationSchema: disableSchema });

const onRegenerate = regenerateForm.handleSubmit(async (values) => {
  loading.value = true;
  const result = await apiCall(
    () => AuthService.regenerateBackupCodes({ code: values.code }),
    { successMessage: 'Backup codes regenerated!' }
  );
  loading.value = false;
  if (result) {
    regeneratedCodes.value = result.backupCodes;
  }
});

const onDisable = disableForm.handleSubmit(async (values) => {
  loading.value = true;
  const result = await apiCall(
    () => AuthService.disableTwoFactor({ password: values.password }),
    { successMessage: 'Two-factor authentication disabled' }
  );
  loading.value = false;
  if (result) {
    showDisable.value = false;
    emit('disabled');
  }
});
</script>
