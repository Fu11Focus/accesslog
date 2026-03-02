<template>
  <div class="flex flex-col gap-3 py-2 px-4 rounded-lg bg-brand-darkest/40 border border-brand-lighter/10">
    <div class="grid grid-cols-2 gap-3">
      <div class="flex flex-col gap-1">
        <span class="text-brand-text/40 text-base">{{ $t('twoFactor.type') }}</span>
        <Select v-model="form.type">
          <SelectTrigger class="w-full">
            <SelectValue :placeholder="$t('twoFactor.type')" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="APP">{{ $t('twoFactor.typeApp') }}</SelectItem>
            <SelectItem value="SMS">{{ $t('twoFactor.typeSms') }}</SelectItem>
            <SelectItem value="HARDWARE">{{ $t('twoFactor.typeHardware') }}</SelectItem>
          </SelectContent>
        </Select>
      </div>
      <div class="flex flex-col gap-1">
        <span class="text-brand-text/40 text-base">{{ $t('twoFactor.title') }}</span>
        <div class="flex items-center gap-2 h-9">
          <button
            type="button"
            class="relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out"
            :class="form.enabled ? 'bg-emerald-500' : 'bg-gray-600'"
            @click="form.enabled = !form.enabled"
          >
            <span
              class="pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out"
              :class="form.enabled ? 'translate-x-4' : 'translate-x-0'"
            />
          </button>
          <span class="text-base text-brand-text">
            {{ form.enabled ? $t('twoFactor.enabled') : $t('twoFactor.disabled') }}
          </span>
        </div>
      </div>
    </div>
    <div class="flex gap-2 justify-end">
      <Button type="button" variant="ghost" size="sm" @click="$emit('cancel')">
        {{ $t('access.cancel') }}
      </Button>
      <Button size="sm" @click="handleSubmit">
        {{ $t('twoFactor.save') }}
      </Button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { TwoFactorService } from '#setup/api/data/repositories/api';

const props = defineProps<{
  accessId: string
  twoFactor?: {
    id: string
    type: string
    enabled: boolean
  }
}>();

const emit = defineEmits<{
  saved: []
  cancel: []
}>();

const { t: $t } = useI18n();

const form = reactive({
  type: props.twoFactor?.type ?? 'APP',
  enabled: props.twoFactor?.enabled ?? true,
});

async function handleSubmit() {
  if (props.twoFactor?.id) {
    await apiCall(
      () => TwoFactorService.twoFactorControllerUpdateTwoFactor(props.twoFactor!.id, {
        type: form.type,
        enabled: form.enabled,
      }),
      { successMessage: $t('twoFactor.updatedSuccessfully') },
    );
  } else {
    await apiCall(
      () => TwoFactorService.twoFactorControllerCreateTwoFactor({
        accessId: props.accessId,
        type: form.type,
        enabled: form.enabled,
      }),
      { successMessage: $t('twoFactor.createdSuccessfully') },
    );
  }
  emit('saved');
}
</script>
