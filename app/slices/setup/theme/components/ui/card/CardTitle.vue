<script setup lang="ts">
import type { HTMLAttributes } from "vue"
import { cn } from '#setup/theme/lib/utils'

const props = defineProps<{
  class?: HTMLAttributes["class"]
}>()
</script>

<template>
  <h3 data-slot="card-title" :class="cn('font-oneday text-4xl text-center', props.class)">
    <slot />
  </h3>
</template>
