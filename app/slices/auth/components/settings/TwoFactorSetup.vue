<template>
  <Card>
    <CardHeader>
      <CardTitle>{{ $t('settings.twoFactor.title') }}</CardTitle>
      <CardDescription>{{ $t('settings.twoFactor.description') }}</CardDescription>
    </CardHeader>
    <CardContent>
      <!-- Step 1: Start setup -->
      <div v-if="setupStep === 'idle'" class="flex flex-col gap-4">
        <p class="text-sm text-gray-400">{{ $t('settings.twoFactor.notEnabled') }}</p>
        <Button @click="startSetup" :disabled="loading">
          {{ $t('settings.twoFactor.enable') }}
        </Button>
      </div>

      <!-- Step 2: Scan QR -->
      <div v-else-if="setupStep === 'scan'" class="flex flex-col gap-4">
        <p class="text-sm text-gray-400">{{ $t('settings.twoFactor.scanQrCode') }}</p>
        <div class="flex justify-center p-4 bg-white rounded-lg">
          <img :src="setupData?.qrCodeDataUrl" alt="QR Code" class="w-48 h-48" />
        </div>
        <div class="flex flex-col gap-2">
          <p class="text-xs text-gray-500">{{ $t('settings.twoFactor.manualEntry') }}</p>
          <code class="text-xs bg-brand-darkest p-2 rounded break-all select-all">{{ setupData?.secret }}</code>
        </div>

        <form class="flex flex-col gap-4" @submit.prevent="onConfirm">
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
          <div class="flex gap-2">
            <Button type="submit" :disabled="loading">{{ $t('settings.twoFactor.verify') }}</Button>
            <Button type="button" variant="ghost" @click="setupStep = 'idle'">{{ $t('back') }}</Button>
          </div>
        </form>
      </div>

      <!-- Step 3: Backup codes -->
      <div v-else-if="setupStep === 'backup'" class="flex flex-col gap-4">
        <p class="text-sm text-green-400 font-medium">{{ $t('settings.twoFactor.enabledSuccess') }}</p>
        <p class="text-sm text-gray-400">{{ $t('settings.twoFactor.backupCodesDescription') }}</p>
        <div class="grid grid-cols-2 gap-2 p-4 bg-brand-darkest rounded-lg">
          <code v-for="code in backupCodes" :key="code" class="text-sm text-brand-text font-mono text-center py-1">
            {{ code }}
          </code>
        </div>
        <p class="text-xs text-yellow-400">{{ $t('settings.twoFactor.backupCodesWarning') }}</p>
        <Button @click="$emit('enabled')">{{ $t('settings.twoFactor.done') }}</Button>
      </div>
    </CardContent>
  </Card>
</template>

<script setup lang="ts">
import { z } from 'zod';
import { toTypedSchema } from '@vee-validate/zod';
import { useForm } from 'vee-validate';
import { AuthService } from '#setup/api/data/repositories/api';
import { apiCall } from '#common/utils/useApi';

defineEmits<{ enabled: [] }>();

const setupStep = ref<'idle' | 'scan' | 'backup'>('idle');
const loading = ref(false);
const setupData = ref<{ qrCodeDataUrl: string; secret: string; otpauthUrl: string } | null>(null);
const backupCodes = ref<string[]>([]);

const confirmSchema = toTypedSchema(z.object({
  code: z.string().length(6),
}));
const confirmForm = useForm({ validationSchema: confirmSchema });

async function startSetup() {
  loading.value = true;
  const result = await apiCall(() => AuthService.setupTwoFactor());
  loading.value = false;
  if (result) {
    setupData.value = result;
    setupStep.value = 'scan';
  }
}

const onConfirm = confirmForm.handleSubmit(async (values) => {
  loading.value = true;
  const result = await apiCall(
    () => AuthService.confirmTwoFactor({ code: values.code }),
    { successMessage: 'Two-factor authentication enabled!' }
  );
  loading.value = false;
  if (result) {
    backupCodes.value = result.backupCodes;
    setupStep.value = 'backup';
  }
});
</script>
