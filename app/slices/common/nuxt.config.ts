
const currentDir = new URL('.', import.meta.url).pathname;

export default defineNuxtConfig({
    alias: {
        '#common': currentDir,
    },
    i18n: {
        defaultLocale: 'en',
        locales: [
            { code: 'en', name: 'en', file: 'en.json' }
        ],
        langDir: currentDir + '/locales',
    }
})