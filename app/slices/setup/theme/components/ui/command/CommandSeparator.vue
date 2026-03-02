<script setup lang="ts">
import type { SeparatorProps } from "reka-ui"
import type { HTMLAttributes } from "vue"
import { reactiveOmit } from "@vueuse/core"
import { Separator } from "reka-ui"
import { cn } from '#setup/theme/lib/utils'

const props = defineProps<SeparatorProps & { class?: HTMLAttributes["class"] }>()

const delegatedProps = reactiveOmit(props, "class")
</script>

<template>
  <Separator
    data-slot="command-separator"
    v-bind="delegatedProps"
    :class="cn('bg-brand-lighter/20 -mx-1 h-px', props.class)"
  >
    <slot />
  </Separator>
</template>
