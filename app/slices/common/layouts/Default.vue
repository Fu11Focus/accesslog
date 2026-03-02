<template>
    <Header />
    <div class="accesslog-text pointer-events-none fixed top-40 text-9xl font-bold uppercase">
        <FingerprintPatternIcon :size="600" class="text-brand-dark" />
    </div>
    <main class="max-w-360 mx-auto h-[calc(100vh-120px)] p-5 overflow-y-scroll">
        <Breadcrumb v-if="breadcrumbs.length" class="mb-4">
            <BreadcrumbList>
                <template v-for="(item, index) in breadcrumbs" :key="index">
                    <BreadcrumbItem>
                        <BreadcrumbLink v-if="item.to" as-child>
                            <NuxtLink :to="item.to">{{ item.label }}</NuxtLink>
                        </BreadcrumbLink>
                        <BreadcrumbPage v-else>{{ item.label }}</BreadcrumbPage>
                    </BreadcrumbItem>
                    <BreadcrumbSeparator v-if="index < breadcrumbs.length - 1" />
                </template>
            </BreadcrumbList>
        </Breadcrumb>
        <slot />
    </main>
    <Footer class="max-w-360 mx-auto p-5 h-10"/>
    <Toaster />
</template>

<script setup lang="ts">
import 'vue-sonner/style.css';
import { Toaster } from '#setup/theme/components/ui/sonner';
import { FingerprintPatternIcon } from 'lucide-vue-next';
import { useBreadcrumbs } from '../composables/useBreadcrumbs';

const { breadcrumbs } = useBreadcrumbs();
</script>

<style>
.accesslog-text {
    width: 100%;
    display: flex;
    justify-content: center;
    mask-image: radial-gradient(ellipse at center, rgba(0,0,0,0.6) 0%, transparent 70%);
    -webkit-mask-image: radial-gradient(ellipse at center, rgba(0,0,0,0.6) 0%, transparent 70%);

}
</style>