<template>
    <Card class="p-10">
        <CardHeader>
            <CardTitle>{{ $t('auth.register') }}</CardTitle>
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
                <FormField v-slot="{ componentField }" name="passwordConfirm">
                    <FormItem>
                        <FormControl>
                            <Input type="password" v-bind="componentField" placeholder="Confirm Password" />
                        </FormControl>
                        <FormMessage />
                    </FormItem>
                </FormField>
                <Button type="submit">{{ $t('auth.register') }}</Button>
                <div class="flex gap-2 justify-between items-center text-gray-500">
                    <Separator class="flex-1 bg-gray-500/20" />
                    <span>{{ $t('auth.or') }}</span>
                    <Separator class="flex-1 bg-gray-500/20" />
                </div>
                <Button type="submit" asChild>
                    <NuxtLink :to="paths.login">{{ $t('auth.login') }}</NuxtLink>
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
import { paths } from '#common/paths';
import { z } from 'zod';
import { toTypedSchema } from '@vee-validate/zod';
import { useForm } from 'vee-validate';
import { useAuthStore } from '../../stores/auth.store';

const authStore = useAuthStore();
const router = useRouter();
const formSchema = toTypedSchema(z.object({
    email: z.string().email(),
    password: z.string().min(8),
    passwordConfirm: z.string().min(8).refine((val) => val === form.values.password, {
        message: 'Passwords do not match',
        path: ['passwordConfirm'],
    }),
}));

const form = useForm({
    validationSchema: formSchema,
});

const onSubmit = form.handleSubmit(async (values) => {
    await authStore.register(values.email, values.password);
    await authStore.login(values.email, values.password);
    if (authStore.isAuthenticated) {
        router.push(paths.home);
    }
});
</script>