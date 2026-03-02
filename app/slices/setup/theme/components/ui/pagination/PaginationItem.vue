<script setup lang="ts">
import type { PaginationListItemProps } from "reka-ui"
import type { HTMLAttributes } from "vue"
import type { ButtonVariants } from '#setup/theme/components/ui/button'
import { reactiveOmit } from "@vueuse/core"
import { PaginationListItem } from "reka-ui"
import { cn } from '#setup/theme/lib/utils'
import { buttonVariants } from '#setup/theme/components/ui/button'

const props = withDefaults(defineProps<PaginationListItemProps & {
  size?: ButtonVariants["size"]
  class?: HTMLAttributes["class"]
  isActive?: boolean
}>(), {
  size: "icon",
})

const delegatedProps = reactiveOmit(props, "class", "size", "isActive")
</script>

<template>
  <PaginationListItem
    data-slot="pagination-item"
    v-bind="delegatedProps"
    :class="cn(
      buttonVariants({
        variant: isActive ? 'outline' : 'ghost',
        size,
      }),
      isActive ? 'border-brand-lighter/40 text-brand-text bg-brand-darkest/60' : 'text-brand-text/60 hover:text-brand-text',
      props.class)"
  >
    <slot />
  </PaginationListItem>
</template>
