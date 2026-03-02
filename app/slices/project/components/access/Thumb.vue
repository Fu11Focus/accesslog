<template>
  <Card class="bg-brand-darkest/60 border-brand-lighter/30 backdrop-blur-sm">
    <CardContent class="flex flex-col gap-3">
      <div class="flex items-start justify-between">
        <div class="flex flex-col gap-1">
          <span class="text-brand-text font-medium">{{ access.serviceName || 'Unnamed service' }}</span>
          <div v-if="access.serviceUrl" class="flex items-center gap-1">
            <a :href="access.serviceUrl" target="_blank"
              class="text-brand-lighter/60 text-base hover:text-brand-lighter transition-colors truncate max-w-xs">
              {{ access.serviceUrl }}
            </a>
            <button type="button" class="text-brand-lighter/40 hover:text-brand-lighter shrink-0"
              @click="copyToClipboard(access.serviceUrl, 'url')">
              <CheckIcon v-if="copiedField === 'url'" :size="16" class="text-emerald-400" />
              <CopyIcon v-else :size="16" />
            </button>
          </div>
        </div>
        <div class="flex gap-2">
          <Badge :class="envClass" variant="outline">{{ access.environment.toLowerCase() }}</Badge>
          <Badge class="bg-blue-500/20 text-blue-400 border-blue-500/30" variant="outline">
            {{ access.accessLevel.toLowerCase() }}
          </Badge>
        </div>
      </div>

      <Separator class="bg-brand-lighter/10" />

      <div class="grid grid-cols-2 gap-3 text-base">
        <div>
          <span class="text-brand-text/40 text-base">{{ $t('access.fields.login') }}</span>
          <div class="flex items-center gap-2">
            <p class="text-brand-text">{{ access.login }}</p>
            <button type="button" class="text-brand-lighter/40 hover:text-brand-lighter"
              @click="copyToClipboard(access.login, 'login')">
              <CheckIcon v-if="copiedField === 'login'" :size="16" class="text-emerald-400" />
              <CopyIcon v-else :size="16" />
            </button>
          </div>
        </div>
        <div>
          <span class="text-brand-text/40 text-base">{{ $t('access.fields.password') }}</span>
          <div class="flex items-center gap-2">
            <p class="text-brand-text font-mono">{{ showPassword ? access.password : '********' }}</p>
            <button type="button" class="text-brand-lighter/40 hover:text-brand-lighter"
              @click="copyToClipboard(access.password, 'password')">
              <CheckIcon v-if="copiedField === 'password'" :size="16" class="text-emerald-400" />
              <CopyIcon v-else :size="16" />
            </button>
            <button type="button" class="text-brand-lighter/40 hover:text-brand-lighter text-base"
              @click="showPassword = !showPassword">
              <EyeOffIcon v-if="showPassword" :size="16" />
              <EyeIcon v-else :size="16" />
            </button>
          </div>
        </div>
      </div>

      <div v-if="access.owner || access.notes" class="grid grid-cols-2 gap-3 text-base">
        <div v-if="access.owner">
          <span class="text-brand-text/40 text-base">{{ $t('access.fields.owner') }}</span>
          <p class="text-brand-text">{{ access.owner }}</p>
        </div>
        <div v-if="access.notes">
          <span class="text-brand-text/40 text-base">{{ $t('access.fields.notes') }}</span>
          <p class="text-brand-text/70">{{ access.notes }}</p>
        </div>
      </div>

      <div class="flex gap-2 justify-end">
        <Button variant="ghost" size="sm" class="gap-1" @click="showLogs = !showLogs">
          <HistoryIcon :size="14" />
          {{ $t('activityLog.title') }}
          <ChevronDownIcon :size="16" class="transition-transform" :class="{ 'rotate-180': showLogs }" />
        </Button>
        <Button variant="ghost" size="sm" class="gap-1" @click="show2FA = !show2FA">
          <ShieldIcon :size="14" />
          2FA
          <ChevronDownIcon :size="16" class="transition-transform" :class="{ 'rotate-180': show2FA }" />
        </Button>
        <Button variant="ghost" size="sm" @click="$emit('edit')">
          <PencilIcon :size="14" class="mr-1" />
        </Button>
        <Button variant="ghost" size="sm" class="text-red-400 hover:text-red-300" @click="$emit('delete')">
          <TrashIcon :size="14" class="mr-1" />
        </Button>
      </div>

      <!-- Activity Log Section -->
      <template v-if="showLogs">
        <Separator class="bg-brand-lighter/10" />
        <AccessActivityLog :access-id="access.id" />
      </template>

      <!-- 2FA Section -->
      <template v-if="show2FA">
        <Separator class="bg-brand-lighter/10" />
        <TwoFactorProvider :access-id="access.id" />
      </template>
    </CardContent>
  </Card>
</template>

<script setup lang="ts">
import { PencilIcon, TrashIcon, ShieldIcon, ChevronDownIcon, CopyIcon, CheckIcon, EyeIcon, EyeOffIcon, HistoryIcon } from 'lucide-vue-next';

const copiedField = ref<string | null>(null);

function copyToClipboard(value: string | undefined, field: string) {
  if (!value) return;
  navigator.clipboard.writeText(value);
  copiedField.value = field;
  setTimeout(() => copiedField.value = null, 1500);
}

const props = defineProps<{
  access: {
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

defineEmits<{
  edit: []
  delete: []
}>();

const showPassword = ref(false);
const show2FA = ref(false);
const showLogs = ref(false);

const envClass = computed(() => {
  const env = (props.access?.environment ?? '').toUpperCase();
  switch (env) {
    case 'PRODUCTION': return 'bg-red-500/20 text-red-400 border-red-500/30';
    case 'STAGING': return 'bg-amber-500/20 text-amber-400 border-amber-500/30';
    case 'DEVELOPMENT': return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30';
    default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
  }
});
</script>
