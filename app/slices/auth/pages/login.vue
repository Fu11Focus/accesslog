<template>
    <Card class="p-10">
        <CardHeader>
            <CardTitle>Login</CardTitle>
        </CardHeader>
        <CardContent>
            <form class="flex flex-col gap-5 font-montserrat min-w-96">
                <Input type="email" id="email" v-model="email" placeholder="Email" />
                <Input type="password" id="password" v-model="password" placeholder="Password" />
                <Button type="submit">{{ $t('auth.signIn') }}</Button>
            </form>
        </CardContent>
    </Card>
</template>

<script setup lang="ts">
definePageMeta({ layout: 'auth' })
</script>