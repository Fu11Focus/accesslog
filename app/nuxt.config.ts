import { registerSlices } from './registerSlices';

// https://nuxt.com/docs/api/configuration/nuxt-config
export default defineNuxtConfig({
  compatibilityDate: '2025-07-15',
  devtools: { enabled: false },
  runtimeConfig: {
    public: {
      apiBase: 'http://localhost:3333',
    },
  },
  extends: ['./slices/setup', './slices/common', ...registerSlices()],
  modules: ['@pinia/nuxt', '@nuxtjs/i18n', 'shadcn-nuxt', '@vee-validate/nuxt',],
  i18n: {
    defaultLocale: 'en',
    locales: [
      { code: 'en', name: 'English' }
    ]
  },
  css: ['#setup/theme/css/tailwind.css'],
  shadcn: {
    /**
     * Prefix for all the imported component.
     * @default "Ui"
     */
    prefix: '',
    /**
     * Directory that the component lives in.
     * Will respect the Nuxt aliases.
     * @link https://nuxt.com/docs/api/nuxt-config#alias
     * @default "@/components/ui"
     */
    componentDir: '#setup/theme/components/ui'
  }
})