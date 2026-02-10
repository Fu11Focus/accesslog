
const currentDir = new URL('.', import.meta.url).pathname;

export default defineNuxtConfig({
    alias: {
        '#auth': currentDir,
    },
})