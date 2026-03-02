<template>
  <div class="flex flex-col gap-3">
    <div class="flex items-center justify-between">
      <span class="text-base font-medium text-brand-text/60">{{ $t('twoFactor.recoveryCodes') }}</span>
      <Button v-if="!showAddForm" variant="ghost" size="sm" class="gap-1 h-7 text-base" @click="showAddForm = true">
        {{ $t('twoFactor.addCode') }}
      </Button>
    </div>

    <!-- Add code form -->
    <div v-if="showAddForm" class="flex gap-2">
      <Input
        v-model="newCode"
        :placeholder="$t('twoFactor.codePlaceholder')"
        class="h-8 text-base"
      />
      <Button size="sm" class="h-8" @click="handleAddCode">
        {{ $t('twoFactor.save') }}
      </Button>
      <Button variant="ghost" size="sm" class="h-8" @click="showAddForm = false; newCode = ''">
        {{ $t('access.cancel') }}
      </Button>
    </div>

    <!-- Empty state -->
    <p v-if="!codes?.length && !showAddForm" class="text-brand-text/30 text-base py-2">
      {{ $t('twoFactor.noRecoveryCodes') }}
    </p>

    <!-- Codes list -->
    <div v-if="codes?.length" class="flex flex-col gap-1.5">
      <div
        v-for="code in codes"
        :key="code.id"
        class="flex items-center justify-between py-1.5 px-3 rounded bg-brand-darkest/60 border border-brand-lighter/10"
      >
        <div class="flex items-center gap-2">
          <span
            class="font-mono text-base"
            :class="code.used ? 'text-brand-text/20 line-through' : 'text-brand-text'"
          >
            {{ code.code || '••••••••' }}
          </span>
          <Badge
            :class="code.used
              ? 'bg-gray-500/20 text-gray-400 border-gray-500/30'
              : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'"
            variant="outline"
            class="text-[9px] px-1 py-0"
          >
            {{ code.used ? $t('twoFactor.codeUsed') : $t('twoFactor.codeAvailable') }}
          </Badge>
        </div>
        <div class="flex gap-1">
          <Button
            v-if="!code.used"
            variant="ghost"
            size="sm"
            class="h-6 w-6 p-0 text-amber-400 hover:text-amber-300"
            @click="handleUseCode(code.id)"
          >
            <CheckIcon :size="16" />
          </Button>
          <Button
            variant="ghost"
            size="sm"
            class="h-6 w-6 p-0 text-red-400 hover:text-red-300"
            @click="handleDeleteCode(code.id)"
          >
            <XIcon :size="16" />
          </Button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { CheckIcon, XIcon } from 'lucide-vue-next';
import { RecoveryCodeService } from '#setup/api/data/repositories/api';

const props = defineProps<{
  twoFactorId: string
}>();

const { t: $t } = useI18n();
const showAddForm = ref(false);
const newCode = ref('');

const { data: codes, refresh } = await useAsyncData(
  `recovery-codes-${props.twoFactorId}`,
  () => RecoveryCodeService.getRecoveryCodeByTwoFactorId(props.twoFactorId),
  { server: false, default: () => [] },
);

async function handleAddCode() {
  if (!newCode.value.trim()) return;
  await apiCall(
    () => RecoveryCodeService.createRecoveryCode({
      twoFactorId: props.twoFactorId,
      code: newCode.value.trim(),
    }),
    { successMessage: $t('twoFactor.codeCreatedSuccessfully') },
  );
  newCode.value = '';
  showAddForm.value = false;
  await refresh();
}

async function handleUseCode(id: string) {
  await apiCall(
    () => RecoveryCodeService.useRecoveryCode(id),
    { successMessage: $t('twoFactor.codeUsedSuccessfully') },
  );
  await refresh();
}

async function handleDeleteCode(id: string) {
  await apiCall(
    () => RecoveryCodeService.deleteRecoveryCode(id),
    { successMessage: $t('twoFactor.codeDeletedSuccessfully') },
  );
  await refresh();
}
</script>
