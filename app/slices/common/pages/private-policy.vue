<template>
  <div class="flex flex-col gap-8 max-w-3xl text-brand-text/80 leading-relaxed">
    <h1 class="text-3xl font-bold text-brand-text font-montserrat">{{ $t('url.policy') }}</h1>
    <p class="text-sm text-brand-text/50">Last updated: February 24, 2026</p>

    <section class="flex flex-col gap-3">
      <h2 class="text-xl font-semibold text-brand-text">1. Introduction</h2>
      <p>This Privacy Policy describes how AccessLog ("we", "our", "the Service") collects, uses, and protects your personal information. We are committed to ensuring your privacy and the security of your data.</p>
    </section>

    <section class="flex flex-col gap-3">
      <h2 class="text-xl font-semibold text-brand-text">2. Information We Collect</h2>
      <h3 class="text-lg font-medium text-brand-text/90">2.1 Account Information</h3>
      <p>When you register, we collect:</p>
      <ul class="list-disc pl-6 flex flex-col gap-1">
        <li><strong class="text-brand-text">Email address</strong> — used for authentication and account recovery</li>
        <li><strong class="text-brand-text">Password hash</strong> — your password is hashed using bcrypt and never stored in plain text</li>
        <li><strong class="text-brand-text">Encryption salt</strong> — a randomly generated value used for key derivation</li>
      </ul>

      <h3 class="text-lg font-medium text-brand-text/90 mt-2">2.2 Stored Credentials</h3>
      <p>The credentials you store (service names, URLs, logins, passwords, notes) are encrypted using AES-256-CBC encryption before being saved to our database. We do not have access to your decrypted data.</p>

      <h3 class="text-lg font-medium text-brand-text/90 mt-2">2.3 Activity Logs</h3>
      <p>We automatically log actions performed on your credentials (creation, viewing, updates, deletion) for audit purposes. These logs are visible only to you.</p>

      <h3 class="text-lg font-medium text-brand-text/90 mt-2">2.4 Technical Data</h3>
      <p>We may collect standard technical information such as IP address, browser type, and access timestamps for security monitoring and service improvement.</p>
    </section>

    <section class="flex flex-col gap-3">
      <h2 class="text-xl font-semibold text-brand-text">3. How We Use Your Information</h2>
      <p>We use collected information to:</p>
      <ul class="list-disc pl-6 flex flex-col gap-1">
        <li>Provide and maintain the Service</li>
        <li>Authenticate your identity and manage your sessions</li>
        <li>Encrypt and decrypt your stored credentials</li>
        <li>Generate activity logs for your account</li>
        <li>Monitor for unauthorized access and security threats</li>
        <li>Communicate important updates about the Service</li>
      </ul>
    </section>

    <section class="flex flex-col gap-3">
      <h2 class="text-xl font-semibold text-brand-text">4. Encryption & Zero-Knowledge Architecture</h2>
      <p>AccessLog uses a zero-knowledge encryption model:</p>
      <ul class="list-disc pl-6 flex flex-col gap-1">
        <li>Your encryption key is derived from your password using <strong class="text-brand-text">PBKDF2-SHA512</strong> with 100,000 iterations</li>
        <li>The derived key is never stored on our servers permanently</li>
        <li>All sensitive data is encrypted client-side with <strong class="text-brand-text">AES-256-CBC</strong> before storage</li>
        <li>We cannot read, access, or recover your encrypted data</li>
        <li>If you forget your password, your encrypted data cannot be recovered</li>
      </ul>
    </section>

    <section class="flex flex-col gap-3">
      <h2 class="text-xl font-semibold text-brand-text">5. Data Storage & Retention</h2>
      <p>Your data is stored in encrypted form in our PostgreSQL database. Session data is stored temporarily in Redis with a 7-day expiration. We retain your data for as long as your account is active. Upon account deletion, all your data is permanently removed.</p>
    </section>

    <section class="flex flex-col gap-3">
      <h2 class="text-xl font-semibold text-brand-text">6. Data Sharing</h2>
      <p>We do not sell, trade, or share your personal information with third parties. We may disclose information only if required by law or to protect the security of the Service.</p>
    </section>

    <section class="flex flex-col gap-3">
      <h2 class="text-xl font-semibold text-brand-text">7. Cookies & Session Management</h2>
      <p>We use the following cookies:</p>
      <ul class="list-disc pl-6 flex flex-col gap-1">
        <li><strong class="text-brand-text">Refresh token cookie</strong> — an HTTP-only, secure cookie used for session management (7-day expiration)</li>
        <li><strong class="text-brand-text">Access token</strong> — stored in local storage for API authentication (15-minute expiration)</li>
      </ul>
      <p>We do not use tracking cookies, analytics services, or third-party advertising.</p>
    </section>

    <section class="flex flex-col gap-3">
      <h2 class="text-xl font-semibold text-brand-text">8. Your Rights</h2>
      <p>You have the right to:</p>
      <ul class="list-disc pl-6 flex flex-col gap-1">
        <li><strong class="text-brand-text">Access</strong> — view all data associated with your account</li>
        <li><strong class="text-brand-text">Rectification</strong> — update or correct your account information</li>
        <li><strong class="text-brand-text">Deletion</strong> — permanently delete your account and all associated data</li>
        <li><strong class="text-brand-text">Portability</strong> — export your data in a standard format</li>
        <li><strong class="text-brand-text">Withdrawal of consent</strong> — stop using the Service at any time</li>
      </ul>
    </section>

    <section class="flex flex-col gap-3">
      <h2 class="text-xl font-semibold text-brand-text">9. Security Measures</h2>
      <p>We implement the following security measures to protect your data:</p>
      <ul class="list-disc pl-6 flex flex-col gap-1">
        <li>End-to-end encryption for all stored credentials</li>
        <li>Bcrypt password hashing with salt</li>
        <li>CORS protection and CSRF mitigation</li>
        <li>HTTP-only cookies for refresh tokens</li>
        <li>JWT-based authentication with short-lived access tokens</li>
        <li>Rate limiting and input validation on all endpoints</li>
      </ul>
    </section>

    <section class="flex flex-col gap-3">
      <h2 class="text-xl font-semibold text-brand-text">10. Changes to This Policy</h2>
      <p>We may update this Privacy Policy from time to time. We will notify you of significant changes via email or through the Service. The "Last updated" date at the top of this page indicates when the policy was last revised.</p>
    </section>

    <section class="flex flex-col gap-3">
      <h2 class="text-xl font-semibold text-brand-text">11. Contact</h2>
      <p>If you have any questions about this Privacy Policy or your data, please contact us through the <NuxtLink :to="paths.contact" class="text-brand-text underline underline-offset-4 hover:text-brand-text/80">Contacts</NuxtLink> page.</p>
    </section>
  </div>
</template>

<script lang="ts" setup>
import { paths } from '#common/paths';

definePageMeta({ middleware: ['auth'] })
</script>
