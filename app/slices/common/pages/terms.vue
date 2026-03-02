<template>
  <div class="flex flex-col gap-8 max-w-3xl text-brand-text/80 leading-relaxed">
    <h1 class="text-3xl font-bold text-brand-text font-montserrat">{{ $t('url.terms') }}</h1>
    <p class="text-sm text-brand-text/50">Last updated: February 24, 2026</p>

    <section class="flex flex-col gap-3">
      <h2 class="text-xl font-semibold text-brand-text">1. Acceptance of Terms</h2>
      <p>By accessing or using AccessLog ("the Service"), you agree to be bound by these Terms & Conditions. If you do not agree with any part of these terms, you may not use the Service.</p>
    </section>

    <section class="flex flex-col gap-3">
      <h2 class="text-xl font-semibold text-brand-text">2. Description of Service</h2>
      <p>AccessLog is a credential management platform that allows users to securely store, organize, and manage access credentials for various services and projects. All sensitive data is encrypted using AES-256-CBC encryption with per-user encryption keys derived from your account password.</p>
    </section>

    <section class="flex flex-col gap-3">
      <h2 class="text-xl font-semibold text-brand-text">3. Account Registration</h2>
      <p>To use the Service, you must create an account by providing a valid email address and a secure password. You are responsible for:</p>
      <ul class="list-disc pl-6 flex flex-col gap-1">
        <li>Maintaining the confidentiality of your account credentials</li>
        <li>All activities that occur under your account</li>
        <li>Notifying us immediately of any unauthorized access</li>
        <li>Ensuring your password is strong and unique to this service</li>
      </ul>
    </section>

    <section class="flex flex-col gap-3">
      <h2 class="text-xl font-semibold text-brand-text">4. Data Encryption & Security</h2>
      <p>Your stored credentials are encrypted using industry-standard AES-256-CBC encryption. The encryption key is derived from your account password using PBKDF2 with 100,000 iterations. This means:</p>
      <ul class="list-disc pl-6 flex flex-col gap-1">
        <li>We cannot access or recover your stored passwords</li>
        <li>If you lose your account password, your encrypted data cannot be recovered</li>
        <li>Changing your password will automatically re-encrypt all stored data</li>
      </ul>
    </section>

    <section class="flex flex-col gap-3">
      <h2 class="text-xl font-semibold text-brand-text">5. Acceptable Use</h2>
      <p>You agree not to use the Service to:</p>
      <ul class="list-disc pl-6 flex flex-col gap-1">
        <li>Store credentials obtained through unauthorized means</li>
        <li>Violate any applicable laws or regulations</li>
        <li>Attempt to gain unauthorized access to other users' data</li>
        <li>Interfere with or disrupt the Service's infrastructure</li>
        <li>Use automated tools to scrape or extract data from the Service</li>
      </ul>
    </section>

    <section class="flex flex-col gap-3">
      <h2 class="text-xl font-semibold text-brand-text">6. Data Ownership</h2>
      <p>You retain full ownership of all data you store in AccessLog. We do not claim any rights to your stored credentials, project information, or other content. You may export or delete your data at any time.</p>
    </section>

    <section class="flex flex-col gap-3">
      <h2 class="text-xl font-semibold text-brand-text">7. Service Availability</h2>
      <p>We strive to maintain high availability of the Service, but we do not guarantee uninterrupted access. The Service may be temporarily unavailable due to maintenance, updates, or circumstances beyond our control. We are not liable for any loss or damage resulting from service interruptions.</p>
    </section>

    <section class="flex flex-col gap-3">
      <h2 class="text-xl font-semibold text-brand-text">8. Limitation of Liability</h2>
      <p>The Service is provided "as is" without warranties of any kind. To the maximum extent permitted by law, AccessLog shall not be liable for any indirect, incidental, special, or consequential damages, including but not limited to loss of data, loss of profits, or business interruption.</p>
    </section>

    <section class="flex flex-col gap-3">
      <h2 class="text-xl font-semibold text-brand-text">9. Account Termination</h2>
      <p>We reserve the right to suspend or terminate your account if you violate these terms. You may delete your account at any time. Upon account deletion, all associated data will be permanently removed from our systems.</p>
    </section>

    <section class="flex flex-col gap-3">
      <h2 class="text-xl font-semibold text-brand-text">10. Changes to Terms</h2>
      <p>We may update these Terms & Conditions from time to time. We will notify you of significant changes via email or through the Service. Your continued use of the Service after changes take effect constitutes acceptance of the updated terms.</p>
    </section>

    <section class="flex flex-col gap-3">
      <h2 class="text-xl font-semibold text-brand-text">11. Contact</h2>
      <p>If you have any questions about these Terms & Conditions, please contact us through the <NuxtLink :to="paths.contact" class="text-brand-text underline underline-offset-4 hover:text-brand-text/80">Contacts</NuxtLink> page.</p>
    </section>
  </div>
</template>

<script lang="ts" setup>
import { paths } from '#common/paths';

definePageMeta({ middleware: ['auth'] })
</script>
