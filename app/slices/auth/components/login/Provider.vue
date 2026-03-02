<template>
    <Card class="p-10">
        <CardHeader>
            <CardTitle>{{ step === 'totp' ? $t('auth.twoFactorTitle') : $t('auth.login') }}</CardTitle>
        </CardHeader>
        <CardContent class="font-montserrat min-w-96 max-w-96">
            <!-- Step 1: Credentials -->
            <form v-if="step === 'credentials'" class="flex flex-col gap-5" @submit.prevent="onSubmitCredentials">
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
                <div class="text-base text-gray-500 font-normal text-center">
                    By continuing, you acknowledge that you understand and agree to the Terms & Conditions and Privacy
                    Policy
                </div>
            </form>

            <!-- Step 2: TOTP Code -->
            <form v-else-if="step === 'totp'" class="flex flex-col gap-5" @submit.prevent="onSubmitTotp">
                <p class="text-sm text-gray-400">{{ $t('auth.enterTotpCode') }}</p>
                <div class="flex flex-col gap-2">
                    <Input
                        v-model="totpCode"
                        type="text"
                        inputmode="numeric"
                        autocomplete="one-time-code"
                        maxlength="8"
                        :placeholder="$t('auth.codePlaceholder')"
                    />
                    <p v-if="totpError" class="text-sm text-red-500">{{ totpError }}</p>
                </div>
                <Button type="submit">{{ $t('auth.verify') }}</Button>
                <Button type="button" variant="ghost" @click="step = 'credentials'; authStore.pendingTwoFactor = null">
                    {{ $t('back') }}
                </Button>
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
const step = ref<'credentials' | 'totp'>('credentials');

// Credentials form (vee-validate)
const formSchema = toTypedSchema(z.object({
  email: z.string().email(),
  password: z.string().min(8),
}));
const form = useForm({ validationSchema: formSchema });

const onSubmitCredentials = form.handleSubmit(async (values) => {
    await apiCall(
        () => authStore.login(values.email, values.password),
        { successMessage: authStore.pendingTwoFactor ? undefined : 'Welcome back!' }
    );

    if (authStore.pendingTwoFactor) {
        step.value = 'totp';
        return;
    }

    if (authStore.isAuthenticated) {
        router.push(paths.home);
    }
});

// TOTP form (manual - avoids useForm conflict)
const totpCode = ref('');
const totpError = ref('');

async function onSubmitTotp() {
    totpError.value = '';
    const code = totpCode.value.trim();
    if (code.length < 6) {
        totpError.value = 'Code must be at least 6 characters';
        return;
    }

    await apiCall(
        () => authStore.verifyTwoFactor(code),
        { successMessage: 'Welcome back!' }
    );

    if (authStore.isAuthenticated) {
        router.push(paths.home);
    }
}
</script>
