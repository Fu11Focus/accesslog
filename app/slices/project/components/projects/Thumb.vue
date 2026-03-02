<script setup lang="ts">
import {paths} from '#common/paths';

defineProps<{
  project: {
      id: string,
      name: string,
      clientName: string,
      status: string,
      description: string,
      createdAt: Date,
  }
}>();

function formatDate(date: string) {
  return new Date(date).toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  })
}

</script>
<template>
  <Card
    @click="$router.push(paths.projectsEdit(project.id))"
    class="bg-brand-darkest/60 border-brand-lighter/30 backdrop-blur-sm hover:outline-2 hover:outline-brand-lighter/60 transition-colors cursor-pointer flex flex-col">
    <CardHeader class="pb-3 px-0">
      <div class="flex items-start justify-between">
        <CardTitle class="text-brand-text text-lg text-left">{{ project.name }}</CardTitle>
        <Badge :class="project.status === 'ACTIVE'
          ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
          : 'bg-gray-500/20 text-gray-400 border-gray-500/30'" variant="outline">
          {{ project.status.toLowerCase() }}
        </Badge>
      </div>
    </CardHeader>
    <CardContent class="flex flex-col flex-1 gap-3 justify-between">
      <p class="text-brand-text/50 text-base">{{ project.description }}</p>
      <div class="flex items-center justify-between text-base text-brand-text/40">
        <span>{{ project.clientName }}</span>
        <span>{{ formatDate(project.createdAt.toString()) }}</span>
      </div>
    </CardContent>
  </Card>

</template>
