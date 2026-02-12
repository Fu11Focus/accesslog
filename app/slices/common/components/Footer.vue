<script lang="ts" setup>
import { paths } from '#common/paths';
</script>

<template>
    <footer class="flex items-center w-full justify-center gap-4 text-brand-text font-thin">
        <NuxtLink :to="paths.terms">{{ $t('url.terms') }}</NuxtLink>
        <NuxtLink :to="paths.policy">{{ $t('url.policy') }}</NuxtLink>
        <NuxtLink :to="paths.contact">{{ $t('url.contacts') }}</NuxtLink>
    </footer>
</template>