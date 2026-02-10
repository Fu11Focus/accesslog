<script setup lang="ts">
import { FingerprintPatternIcon, LightbulbIcon } from 'lucide-vue-next';

</script>

<template>
    <header class="flex items-center justify-between max-w-[1440px] mx-auto gap-40 p-4 bg-foreground text-background">
        <div class="flex items-center gap-2">
            <h1 class="text-2xl font-bold">AccessLog</h1>
            <FingerprintPatternIcon class="w-8 h-8" />
        </div>
        <div class="flex-1">
            <Input />
        </div>
        <div class="flex gap-2">
            <Button variant="outline">
                {{ $t('Create Project') }}
            </Button>
            <Button variant="outline">
                <LightbulbIcon />
            </Button>
        </div>
    </header>
</template>