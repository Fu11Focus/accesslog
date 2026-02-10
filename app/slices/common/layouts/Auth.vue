<script setup lang="ts">
</script>

<template>
    <div class="bg-black green-light">
        <div class="accesslog-text fixed top-40 text-9xl font-bold uppercase">
            AccessLog
        </div>
        <main class="max-w-[1440px] mx-auto h-[calc(100vh-12rem)] p-5">
            <div class="flex items-center justify-center h-full">
                <slot />
            </div>
        </main>
        <Footer />
    </div>
</template>

<style scoped>
.accesslog-text {
    background: radial-gradient(ellipse at top, rgba(51, 99, 87, 0.45) 0%, rgba(55, 82, 77, 0.4) 30%, transparent 85%);
    -webkit-background-clip: text;
    background-clip: text;
    color: transparent;
}

.green-light {
    display: flex;
    justify-content: center;
    align-items: center;
    position: absolute;
    width: 100%;
    height: 100%;
    background-image: radial-gradient(ellipse at top, #336357 0%, #37524D 5%, transparent 50%);
}
</style>