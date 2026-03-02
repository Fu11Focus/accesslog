<script setup lang="ts">
import type { HTMLAttributes } from "vue"
import { cn } from '#setup/theme/lib/utils'

const props = defineProps<{
  class?: HTMLAttributes["class"]
}>()
</script>

<template>
  <p
    data-slot="card-description"
    :class="cn('text-muted-foreground text-base', props.class)"
  >
    <slot />
  </p>
</template>
