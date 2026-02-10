
const currentDir = new URL('.', import.meta.url).pathname;

export default defineNuxtConfig({
    alias: {
        '#setup': currentDir,
    },

    modules: ['@nuxtjs/tailwindcss'],
    css: [currentDir + '/theme/css/fonts.css'],
    tailwindcss: {
        cssPath: currentDir + '/theme/css/tailwind.css',
    },
})