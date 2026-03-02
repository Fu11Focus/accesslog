<template>
  <div class="flex flex-col gap-6 max-w-lg">
    <h2 class="text-2xl font-bold text-brand-text font-montserrat">{{ $t('settings.title') }}</h2>

    <Card>
      <CardHeader>
        <CardTitle>{{ $t('settings.changePassword') }}</CardTitle>
      </CardHeader>
      <CardContent>
        <form class="flex flex-col gap-5" @submit.prevent="onSubmit">
          <FormField v-slot="{ componentField }" name="currentPassword">
            <FormItem>
              <FormLabel>{{ $t('settings.currentPassword') }}</FormLabel>
              <FormControl>
                <Input type="password" v-bind="componentField" />
              </FormControl>
              <FormMessage />
            </FormItem>
          </FormField>
          <FormField v-slot="{ componentField }" name="newPassword">
            <FormItem>
              <FormLabel>{{ $t('settings.newPassword') }}</FormLabel>
              <FormControl>
                <Input type="password" v-bind="componentField" />
              </FormControl>
              <FormMessage />
            </FormItem>
          </FormField>
          <FormField v-slot="{ componentField }" name="confirmPassword">
            <FormItem>
              <FormLabel>{{ $t('settings.confirmPassword') }}</FormLabel>
              <FormControl>
                <Input type="password" v-bind="componentField" />
              </FormControl>
              <FormMessage />
            </FormItem>
          </FormField>
          <Button type="submit">{{ $t('settings.save') }}</Button>
        </form>
      </CardContent>
    </Card>

    <!-- Two-Factor Authentication -->
    <TwoFactorSetup v-if="!twoFactorEnabled" @enabled="onTwoFactorChanged" />
    <TwoFactorDisable v-else @disabled="onTwoFactorChanged" />
  </div>
</template>

<script setup lang="ts">
import { z } from 'zod';
import { toTypedSchema } from '@vee-validate/zod';
import { useForm } from 'vee-validate';
import { AuthService } from '#setup/api/data/repositories/api';
import { useAuthStore } from '#auth/stores/auth.store';
import { apiCall } from '#common/utils/useApi';
import { paths } from '#common/paths';
import TwoFactorSetup from '#auth/components/settings/TwoFactorSetup.vue';
import TwoFactorDisable from '#auth/components/settings/TwoFactorDisable.vue';

const { t } = useI18n();
const authStore = useAuthStore();
const router = useRouter();

const twoFactorEnabled = ref(authStore.user?.twoFactorEnabled ?? false);

const formSchema = toTypedSchema(z.object({
  currentPassword: z.string().min(6),
  newPassword: z.string().min(6),
  confirmPassword: z.string().min(6),
}).refine((data) => data.newPassword === data.confirmPassword, {
  message: t('settings.passwordsMismatch'),
  path: ['confirmPassword'],
}));

const form = useForm({ validationSchema: formSchema });

const onSubmit = form.handleSubmit(async (values) => {
  const result = await apiCall(
    () => AuthService.changePassword({
      currentPassword: values.currentPassword,
      newPassword: values.newPassword,
    }),
    { successMessage: t('settings.passwordChanged') },
  );

  if (result) {
    authStore.setTokens(result.accessToken);
    router.push(paths.home);
  }
});

async function onTwoFactorChanged() {
  await authStore.fetchMe();
  twoFactorEnabled.value = authStore.user?.twoFactorEnabled ?? false;
}
</script>
