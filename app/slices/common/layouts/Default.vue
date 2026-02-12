<template>
    <Header />
    <div class="accesslog-text fixed top-40 text-9xl font-bold uppercase">
        <FingerprintPatternIcon :size="600" class="text-brand-dark" />
    </div>
    <main class="max-w-360 mx-auto h-[calc(100vh-120px)] p-5">
        <slot />
    </main>
    <Footer class="max-w-360 mx-auto p-5 h-10"/>
    <Toaster />
</template>

<script setup lang="ts">
import 'vue-sonner/style.css';
import { Toaster } from '#setup/theme/components/ui/sonner';
import { FingerprintPatternIcon } from 'lucide-vue-next';

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