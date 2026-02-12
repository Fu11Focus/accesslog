<template>
    <Card class="p-10">
        <CardHeader>
            <CardTitle>{{ $t('auth.login') }}</CardTitle>
        </CardHeader>
        <CardContent class="font-montserrat min-w-96 max-w-96">
            <form class="flex flex-col gap-5" @submit.prevent="onSubmit">
                <FormField v-slot="{ componentField }" name="email">
                    <FormItem>
                        <FormControl>
                            <Input type="email" v-bind="componentField" placeholder="Email" />
                        </FormControl>
                        <FormMessage />
                    </FormItem>
                </FormField>
                <FormField v-slot="{ componentField }" name="password">
                    <FormItem>
                        <FormControl>
                            <Input type="password" v-bind="componentField" placeholder="Password" />
                        </FormControl>
                        <FormMessage />
                    </FormItem>
                </FormField>
                <Button type="submit">{{ $t('auth.signIn') }}</Button>
                <div class="flex gap-2 justify-between items-center text-gray-500">
                    <Separator class="flex-1 bg-gray-500/20" />
                    <span>{{ $t('auth.or') }}</span>
                    <Separator class="flex-1 bg-gray-500/20" />
                </div>
                <Button as-child>
                    <NuxtLink :to="paths.register">{{ $t('auth.register') }}</NuxtLink>
                </Button>
                <div class="text-xs text-gray-500 font-normal text-center">
                    By continuing, you acknowledge that you understand and agree to the Terms & Conditions and Privacy
                    Policy
                </div>
            </form>
        </CardContent>
    </Card>
</template>

<script setup lang="ts">
import { z } from 'zod';
import { toTypedSchema } from '@vee-validate/zod';
import { paths } from '#common/paths';
import { useAuthStore } from '../../stores/auth.store';
import { useForm } from 'vee-validate';
import { apiCall } from '../../../common/utils/useApi';

const authStore = useAuthStore();
const router = useRouter();
const formSchema = toTypedSchema(z.object({
  email: z.string().email(),
  password: z.string().min(8),
}))

const form = useForm({
  validationSchema: formSchema,
})

const onSubmit = form.handleSubmit(async (values) => {
    await apiCall(
        () => authStore.login(values.email, values.password),
        { successMessage: 'Welcome back!', }
    );

  if (authStore.isAuthenticated) {
    router.push(paths.home);
  }
});

</script>