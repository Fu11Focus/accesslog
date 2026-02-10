
const currentDir = new URL('.', import.meta.url).pathname;

export default defineNuxtConfig({
    alias: {
        '#api': currentDir,
    },
    runtimeConfig: {
        public: {
            BASE: process.env.API_URL,
        },
    },
})