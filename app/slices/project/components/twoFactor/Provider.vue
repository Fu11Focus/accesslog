<template>
  <div class="flex flex-col gap-4">
    <div class="flex items-center justify-between">
      <h4 class="text-base font-semibold text-brand-text font-montserrat flex items-center gap-2">
        <ShieldIcon :size="16" class="text-brand-lighter" />
        {{ $t('twoFactor.title') }}
      </h4>
      <Badge
        v-if="twoFactor"
        :class="twoFactor.enabled
          ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
          : 'bg-gray-500/20 text-gray-400 border-gray-500/30'"
        variant="outline"
        class="text-[10px] px-1.5 py-0"
      >
        {{ twoFactor.enabled ? $t('twoFactor.enabled') : $t('twoFactor.disabled') }}
      </Badge>
    </div>

    <!-- No 2FA configured -->
    <div v-if="!twoFactor && !showSetup" class="flex items-center justify-between py-3 px-4 rounded-lg border border-dashed border-brand-lighter/20">
      <p class="text-brand-text/40 text-base">{{ $t('twoFactor.notConfigured') }}</p>
      <Button size="sm" variant="ghost" class="gap-1" @click="showSetup = true">
        {{ $t('twoFactor.setup') }}
      </Button>
    </div>

    <!-- Setup form (create) -->
    <TwoFactorForm
      v-if="showSetup && !twoFactor"
      :access-id="accessId"
      @saved="onCreated"
      @cancel="showSetup = false"
    />

    <!-- Existing 2FA config -->
    <div v-if="twoFactor && !editing" class="flex flex-col gap-3">
      <div class="flex items-center justify-between py-2 px-4 rounded-lg bg-brand-darkest/40 border border-brand-lighter/10">
        <div class="flex items-center gap-3">
          <component :is="typeIcon" :size="16" :class="twoFactor.enabled ? 'text-emerald-400' : 'text-gray-400'" />
          <div>
            <p class="text-base text-brand-text">{{ typeLabel }}</p>
            <p class="text-[10px] text-brand-text/40">{{ twoFactor.enabled ? $t('twoFactor.enabled') : $t('twoFactor.disabled') }}</p>
          </div>
        </div>
        <div class="flex gap-1">
          <Button variant="ghost" size="sm" @click="editing = true">
            <PencilIcon :size="14" />
          </Button>
          <Button variant="ghost" size="sm" class="text-red-400 hover:text-red-300" @click="handleDelete">
            <TrashIcon :size="14" />
          </Button>
        </div>
      </div>

      <!-- Recovery Codes section -->
      <TwoFactorRecoveryCodes :two-factor-id="twoFactor.id" />
    </div>

    <!-- Edit form -->
    <TwoFactorForm
      v-if="editing && twoFactor"
      :access-id="accessId"
      :two-factor="twoFactor"
      @saved="onUpdated"
      @cancel="editing = false"
    />
  </div>
</template>

<script setup lang="ts">
import { ShieldIcon, PencilIcon, TrashIcon, SmartphoneIcon, MessageSquareIcon, KeyIcon } from 'lucide-vue-next';
import { TwoFactorService } from '#setup/api/data/repositories/api';

const props = defineProps<{
  accessId: string
}>();

const { t: $t } = useI18n();
const showSetup = ref(false);
const editing = ref(false);

const { data: twoFactor, refresh } = await useAsyncData(
  `two-factor-${props.accessId}`,
  () => TwoFactorService.twoFactorControllerGetTwoFactorByAccessId(props.accessId),
  { server: false, default: () => null },
);

const typeIcons: Record<string, any> = {
  APP: SmartphoneIcon,
  SMS: MessageSquareIcon,
  HARDWARE: KeyIcon,
};

const typeIcon = computed(() => typeIcons[twoFactor.value?.type] ?? ShieldIcon);

const typeLabels: Record<string, string> = {
  APP: 'twoFactor.typeApp',
  SMS: 'twoFactor.typeSms',
  HARDWARE: 'twoFactor.typeHardware',
};

const typeLabel = computed(() => $t(typeLabels[twoFactor.value?.type] ?? 'twoFactor.title'));

async function onCreated() {
  showSetup.value = false;
  await refresh();
}

async function onUpdated() {
  editing.value = false;
  await refresh();
}

async function handleDelete() {
  if (!twoFactor.value) return;
  await apiCall(
    () => TwoFactorService.twoFactorControllerDeleteTwoFactorById(twoFactor.value.id),
    { successMessage: $t('twoFactor.deletedSuccessfully') },
  );
  await refresh();
}
</script>
