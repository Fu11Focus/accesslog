Auth Implementation Plan
Context
Backend API (NestJS) is fully implemented with JWT auth (access token 15m + refresh token 7d in httpOnly cookie). Frontend has UI forms and a generated API client, but auth logic is not wired up. The auth store has bugs and is incomplete. No middleware, no API config plugin, no token handling.

Problems in Current Code
slices/auth/stores/auth.store.ts:

response.data — generated API client returns response directly, not .data
login() — backend returns {accessToken, refreshToken, tokenType}, not {user, accessToken}
register() — backend returns user data, not tokens (user must login separately)
refreshToken() — passes this.accessToken as refreshToken (wrong! refresh token is separate, stored in httpOnly cookie)
OpenAPI.TOKEN never set — API requests won't have Authorization header
OpenAPI.BASE never set — all requests go to wrong URL
No User type defined
Missing pieces:

Nuxt plugin to configure OpenAPI.BASE and OpenAPI.TOKEN
Auth middleware (protect pages)
Guest middleware (redirect logged users from login/register)
Form submission in login/register Provider components
Token refresh on 401
Implementation Plan
1. Nuxt Plugin — API Config (slices/auth/plugins/api.ts)
Set OpenAPI.BASE from useRuntimeConfig().public.BASE
Set OpenAPI.TOKEN as a Resolver function that returns useAuthStore().accessToken
Runs on client and server
2. Fix Auth Store (slices/auth/stores/auth.store.ts)

State:
  - user: { id, email } | null
  - accessToken: string | null
  - refreshToken: string | null  (for explicit refresh calls)

Actions:
  login(email, password):
    1. const res = await AuthService.login({ email, password })
    2. this.accessToken = res.accessToken
    3. this.refreshToken = res.refreshToken
    4. Set OpenAPI.TOKEN = res.accessToken
    5. await this.fetchMe()
    6. navigateTo(paths.home)

  register(email, password):
    1. await AuthService.register({ email, password })
    2. navigateTo(paths.login)  // user must login after registration

  logout():
    1. try { await AuthService.authControllerLogout() } catch {}
    2. this.$reset()
    3. OpenAPI.TOKEN = undefined
    4. navigateTo(paths.login)

  refreshToken():
    1. const res = await AuthService.refresh({ refreshToken: this.refreshToken })
    2. this.accessToken = res.accessToken
    3. this.refreshToken = res.refreshToken
    4. OpenAPI.TOKEN = res.accessToken

  fetchMe():
    1. const user = await AuthService.authControllerMe()
    2. this.user = user
    3. this.isAuthenticated = true

  init():  (called by plugin/middleware on app start)
    1. if (this.accessToken) try { await fetchMe() } catch { logout() }
3. Auth Middleware (slices/auth/middleware/auth.global.ts)
Global middleware:

Define public routes: [paths.login, paths.register]
If route is NOT public and !authStore.isAuthenticated → navigateTo(paths.login)
If route IS public (login/register) and authStore.isAuthenticated → navigateTo(paths.home)
This handles both "auth guard" and "guest guard" in one global middleware.

4. Wire Up Login Form (slices/auth/components/login/Provider.vue)
Add @submit.prevent on <form>
Call authStore.login(form.email, form.password)
Add loading state and error handling (try/catch, show error message)
5. Wire Up Register Form (slices/auth/components/register/Provider.vue)
Add @submit.prevent on <form>
Call authStore.register(form.email, form.password)
Add loading state and error handling
Files to Create/Modify
File	Action
slices/auth/plugins/api.ts	Create — configure OpenAPI.BASE and TOKEN
slices/auth/stores/auth.store.ts	Rewrite — fix all bugs, proper token flow
slices/auth/middleware/auth.global.ts	Create — global auth/guest guard
slices/auth/components/login/Provider.vue	Modify — wire form submission
slices/auth/components/register/Provider.vue	Modify — wire form submission
Key Files to Reuse (do not modify)
slices/api/data/repositories/api/services/AuthService.ts — generated API client
slices/api/data/repositories/api/core/OpenAPI.ts — config object (TOKEN, BASE)
slices/common/paths.ts — route paths
Verification
Start backend: cd api && docker-compose up && npm run start:dev
Start frontend: cd app && npm run dev
Go to /login — should see login form
Go to / — should redirect to /login (not authenticated)
Register a user → should redirect to /login
Login with credentials → should redirect to /
Refresh page → should stay on / (token persisted in store)
Check Network tab — API requests should have Authorization: Bearer ... header