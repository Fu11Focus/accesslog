<script setup lang="ts">
import type { HTMLAttributes } from "vue"
import { cn } from '#setup/theme/lib/utils'

const props = defineProps<{
  class?: HTMLAttributes["class"]
}>()
</script>

<template>
  <div data-slot="card"
    :class="cn('bg-black/10 backdrop-blur-md border border-white/10 p-5 rounded-xl text-white', props.class)">
    <slot />
  </div>
</template>
