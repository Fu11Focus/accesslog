<script lang="ts" setup>
import type { HTMLAttributes } from "vue"
import { cn } from '#setup/theme/lib/utils'

const props = defineProps<{
  class?: HTMLAttributes["class"]
}>()
</script>

<template>
  <span
    data-slot="breadcrumb-page"
    role="link"
    aria-disabled="true"
    aria-current="page"
    :class="cn('text-brand-text font-normal', props.class)"
  >
    <slot />
  </span>
</template>
