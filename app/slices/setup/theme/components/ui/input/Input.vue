<script setup lang="ts">
import type { HTMLAttributes } from "vue"
import { useVModel } from "@vueuse/core"
import { cn } from '#setup/theme/lib/utils'

const props = defineProps<{
  defaultValue?: string | number
  modelValue?: string | number
  class?: HTMLAttributes["class"]
  placeholder?: string
}>()

const emits = defineEmits<{
  (e: "update:modelValue", payload: string | number): void
}>()

const modelValue = useVModel(props, "modelValue", emits, {
  passive: true,
  defaultValue: props.defaultValue,
})
</script>

<template>
  <input v-model="modelValue" data-slot="input" :placeholder="placeholder"
    class="bg-black/10 backdrop-blur-md border border-white/10 p-2 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-white/10">
</template>
