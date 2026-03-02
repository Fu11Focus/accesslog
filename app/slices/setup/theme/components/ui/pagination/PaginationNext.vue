<script setup lang="ts">
import type { PaginationNextProps } from "reka-ui"
import type { HTMLAttributes } from "vue"
import type { ButtonVariants } from '#setup/theme/components/ui/button'
import { reactiveOmit } from "@vueuse/core"
import { ChevronRightIcon } from "lucide-vue-next"
import { PaginationNext, useForwardProps } from "reka-ui"
import { cn } from '#setup/theme/lib/utils'
import { buttonVariants } from '#setup/theme/components/ui/button'

const props = withDefaults(defineProps<PaginationNextProps & {
  size?: ButtonVariants["size"]
  class?: HTMLAttributes["class"]
}>(), {
  size: "default",
})

const delegatedProps = reactiveOmit(props, "class", "size")
const forwarded = useForwardProps(delegatedProps)
</script>

<template>
  <PaginationNext
    data-slot="pagination-next"
    :class="cn(buttonVariants({ variant: 'ghost', size }), 'gap-1 px-2.5 sm:pr-2.5 text-brand-text/60 hover:text-brand-text', props.class)"
    v-bind="forwarded"
  >
    <slot>
      <span class="hidden sm:block">Next</span>
      <ChevronRightIcon />
    </slot>
  </PaginationNext>
</template>
