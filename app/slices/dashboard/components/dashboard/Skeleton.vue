<template>
  <div class="flex flex-col gap-6">
    <!-- Welcome skeleton -->
    <div class="flex items-center justify-between">
      <div class="flex flex-col gap-2">
        <Skeleton class="h-8 w-64" />
        <Skeleton class="h-4 w-32" />
      </div>
      <Skeleton class="h-10 w-32 rounded-md" />
    </div>

    <!-- Stats skeleton -->
    <div class="grid grid-cols-2 lg:grid-cols-4 gap-4">
      <Card v-for="i in 4" :key="i" class="bg-brand-darkest/60 border-brand-lighter/30 backdrop-blur-sm">
        <CardContent class="flex items-center gap-3 p-4">
          <Skeleton class="h-10 w-10 rounded-lg" />
          <div class="flex flex-col gap-2">
            <Skeleton class="h-7 w-12" />
            <Skeleton class="h-4 w-20" />
          </div>
        </CardContent>
      </Card>
    </div>

    <!-- Content skeleton -->
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
      <!-- Projects skeleton -->
      <div class="lg:col-span-2 flex flex-col gap-4">
        <div class="flex items-center justify-between">
          <Skeleton class="h-6 w-40" />
          <Skeleton class="h-4 w-16" />
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Card v-for="i in 4" :key="i" class="bg-brand-darkest/60 border-brand-lighter/30 backdrop-blur-sm">
            <CardContent class="flex flex-col gap-3 p-4">
              <div class="flex items-center justify-between">
                <Skeleton class="h-5 w-36" />
                <Skeleton class="h-4 w-14 rounded-full" />
              </div>
              <div class="flex items-center justify-between">
                <Skeleton class="h-4 w-24" />
                <Skeleton class="h-4 w-8" />
              </div>
              <Skeleton class="h-3 w-20" />
            </CardContent>
          </Card>
        </div>
      </div>

      <!-- Right column skeleton -->
      <div class="flex flex-col gap-6">
        <!-- Environments skeleton -->
        <div class="flex flex-col gap-3">
          <Skeleton class="h-6 w-48" />
          <Card class="bg-brand-darkest/60 border-brand-lighter/30 backdrop-blur-sm">
            <CardContent class="flex flex-col gap-3 p-4">
              <div v-for="i in 3" :key="i" class="flex items-center justify-between">
                <Skeleton class="h-5 w-20 rounded-full" />
                <div class="flex items-center gap-2">
                  <Skeleton class="w-24 h-1.5 rounded-full" />
                  <Skeleton class="h-4 w-6" />
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        <!-- Activity skeleton -->
        <div class="flex flex-col gap-3">
          <Skeleton class="h-6 w-36" />
          <Card class="bg-brand-darkest/60 border-brand-lighter/30 backdrop-blur-sm">
            <CardContent class="flex flex-col p-4">
              <div v-for="i in 5" :key="i" class="flex items-start gap-3 py-2.5" :class="{ 'border-t border-brand-lighter/10': i > 1 }">
                <Skeleton class="h-4 w-4 mt-0.5 rounded" />
                <div class="flex-1 flex flex-col gap-1">
                  <Skeleton class="h-4 w-32" />
                  <Skeleton class="h-3 w-48" />
                </div>
                <Skeleton class="h-3 w-10" />
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { Skeleton } from '#setup/theme/components/ui/skeleton';
</script>
