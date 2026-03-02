<template>
  <div class="flex flex-col gap-8 max-w-3xl">
    <h1 class="text-3xl font-bold text-brand-text font-montserrat">{{ $t('contact.title') }}</h1>
    <p class="text-brand-text/60">{{ $t('contact.description') }}</p>

    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
      <Card>
        <CardHeader>
          <div class="flex items-center gap-3">
            <div class="flex items-center justify-center size-10 rounded-lg bg-brand-lighter/20">
              <MailIcon :size="20" class="text-brand-text" />
            </div>
            <CardTitle class="text-lg">{{ $t('contact.email') }}</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          <a href="mailto:support@accesslog.app" class="text-brand-text underline underline-offset-4 hover:text-brand-text/80">support@accesslog.app</a>
          <p class="text-sm text-brand-text/50 mt-1">{{ $t('contact.emailHint') }}</p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <div class="flex items-center gap-3">
            <div class="flex items-center justify-center size-10 rounded-lg bg-brand-lighter/20">
              <GithubIcon :size="20" class="text-brand-text" />
            </div>
            <CardTitle class="text-lg">GitHub</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          <a href="https://github.com/accesslog" target="_blank" rel="noopener" class="text-brand-text underline underline-offset-4 hover:text-brand-text/80">github.com/accesslog</a>
          <p class="text-sm text-brand-text/50 mt-1">{{ $t('contact.githubHint') }}</p>
        </CardContent>
      </Card>
    </div>

    <Card>
      <CardHeader>
        <CardTitle>{{ $t('contact.formTitle') }}</CardTitle>
        <CardDescription>{{ $t('contact.formDescription') }}</CardDescription>
      </CardHeader>
      <CardContent>
        <form class="flex flex-col gap-5" @submit.prevent="onSubmit">
          <FormField v-slot="{ componentField }" name="subject">
            <FormItem>
              <FormLabel>{{ $t('contact.subject') }}</FormLabel>
              <FormControl>
                <Input v-bind="componentField" :placeholder="$t('contact.subjectPlaceholder')" />
              </FormControl>
              <FormMessage />
            </FormItem>
          </FormField>
          <FormField v-slot="{ componentField }" name="message">
            <FormItem>
              <FormLabel>{{ $t('contact.message') }}</FormLabel>
              <FormControl>
                <Textarea v-bind="componentField" :placeholder="$t('contact.messagePlaceholder')" rows="5" />
              </FormControl>
              <FormMessage />
            </FormItem>
          </FormField>
          <Button type="submit" class="self-start">
            <SendIcon :size="16" />
            {{ $t('contact.send') }}
          </Button>
        </form>
      </CardContent>
    </Card>
  </div>
</template>

<script lang="ts" setup>
import { MailIcon, GithubIcon, SendIcon } from 'lucide-vue-next';
import { z } from 'zod';
import { toTypedSchema } from '@vee-validate/zod';
import { useForm } from 'vee-validate';
import { toast } from 'vue-sonner';

definePageMeta({ middleware: ['auth'] })

const { t } = useI18n();

const formSchema = toTypedSchema(z.object({
  subject: z.string().min(3),
  message: z.string().min(10),
}));

const form = useForm({ validationSchema: formSchema });

const onSubmit = form.handleSubmit(async () => {
  toast.success(t('contact.sent'));
  form.resetForm();
});
</script>
