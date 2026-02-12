<template>
   <LoginProvider/>
</template>

<script setup lang="ts">
definePageMeta({ layout: 'auth' , middleware: ['guest']})
</script>