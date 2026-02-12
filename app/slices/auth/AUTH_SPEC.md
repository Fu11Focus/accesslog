# Auth Specification

## API Endpoints

| Endpoint | Method | Auth | Request Body | Response |
|---|---|---|---|---|
| `/auth/login` | POST | - | `AuthDto { email, password }` | `LoginResponseDto { accessToken, refreshToken, tokenType }` |
| `/auth/register` | POST | - | `AuthDto { email, password }` | `UserDto { id, email, plan, createdAt, updatedAt }` |
| `/auth/refresh` | POST | - | `RefreshTokenDto { refreshToken }` (або httpOnly cookie) | `RefreshResponseDto { accessToken, refreshToken }` |
| `/auth/logout` | POST | Bearer | - | `MessageResponseDto { message }` |
| `/auth/logout-all` | POST | Bearer | - | `MessageResponseDto { message }` |
| `/auth/me` | GET | Bearer | - | `MeResponseDto { id, email }` |

### Токени

- **Access token** — JWT, термін дії 15 хвилин, передається в `Authorization: Bearer <token>`
- **Refresh token** — зберігається на бекенді в БД, передається як httpOnly cookie (`refreshToken`, path: `/auth`, maxAge: 7 днів, sameSite: strict, secure: production)

---

## 1. Login

### Передумови
- Користувач на сторінці `/login`
- Layout: `auth`

### Кроки

1. Користувач вводить email та password у форму
2. Валідація на клієнті:
   - email — обовʼязковий, формат email
   - password — обовʼязковий, мін. 6 символів
3. Виклик `AuthService.login({ email, password })` → `POST /auth/login`
4. Бекенд:
   - Шукає користувача в БД за email
   - Перевіряє пароль через bcrypt
   - Генерує JWT access token (15 хв)
   - Генерує refresh token, зберігає в БД
   - Встановлює refresh token як httpOnly cookie
   - Повертає `{ accessToken, refreshToken, tokenType: "Bearer" }`
5. Фронтенд отримує відповідь:
   - Зберігає `accessToken` в Pinia store
   - Встановлює `OpenAPI.TOKEN = accessToken` (щоб всі наступні запити мали Bearer header)
   - Викликає `fetchMe()` для отримання даних користувача
6. `fetchMe()` → `GET /auth/me` з Bearer token
   - Відповідь: `{ id, email }`
   - Зберігає в `state.user`
   - Встановлює `isAuthenticated = true`
7. Редірект на `/` (home)

### Помилки

| HTTP код | Причина | Дія на фронтенді |
|---|---|---|
| 404 | Користувач не знайдений | Показати "User not found" |
| 401 | Невірний пароль | Показати "Invalid password" |
| 400 | Невалідні дані | Показати помилки валідації |
| 500 | Серверна помилка | Показати "Something went wrong" |

---

## 2. Register

### Передумови
- Користувач на сторінці `/register`
- Layout: `auth`

### Кроки

1. Користувач вводить email та password
2. Валідація на клієнті:
   - email — обовʼязковий, формат email
   - password — обовʼязковий, мін. 6 символів
   - confirm password — збігається з password
3. Виклик `AuthService.register({ email, password })` → `POST /auth/register`
4. Бекенд:
   - Перевіряє чи email не зайнятий
   - Хешує пароль через bcrypt
   - Створює користувача в БД
   - Повертає `UserDto { id, email, plan, createdAt, updatedAt }`
5. Фронтенд після успішної реєстрації:
   - Автоматично логінить користувача — викликає `login(email, password)`
   - Далі стандартний login flow (крок 3-7 з Login)

### Помилки

| HTTP код | Причина | Дія на фронтенді |
|---|---|---|
| 409 | Email вже зареєстрований | Показати "User already exists" |
| 400 | Невалідні дані | Показати помилки валідації |
| 500 | Серверна помилка | Показати "Something went wrong" |

---

## 3. Logout

### Кроки

1. Користувач натискає кнопку "Logout"
2. Виклик `AuthService.authControllerLogout()` → `POST /auth/logout` з Bearer token
3. Бекенд:
   - Отримує refresh token з httpOnly cookie
   - Видаляє refresh token з БД (revoke)
   - Очищає httpOnly cookie
   - Повертає `{ message: "Logged out successfully" }`
4. Фронтенд:
   - Очищує `accessToken` зі store
   - Очищує `user` зі store
   - Встановлює `isAuthenticated = false`
   - Скидає `OpenAPI.TOKEN = undefined`
5. Редірект на `/login`

### Logout All (всі пристрої)

- Те саме що й Logout, але викликає `AuthService.authControllerLogoutAll()` → `POST /auth/logout-all`
- Бекенд видаляє ВСІ refresh tokens користувача + очищує encryption key cache
- Всі сесії на інших пристроях стають невалідними

### Помилки

| HTTP код | Причина | Дія на фронтенді |
|---|---|---|
| 401 | Access token невалідний/протухший | Очищуємо стан, редірект на `/login` (без retry) |
| 500 | Серверна помилка | Очищуємо стан локально, редірект на `/login` |

---

## 4. Token Refresh

### Коли відбувається refresh

- Будь-який API запит повернув **401 Unauthorized**
- Access token протух (15 хв пройшло)

### Кроки

1. API запит повертає 401
2. Перевіряємо чи є refresh token (httpOnly cookie відправляється автоматично, бо `credentials: 'include'`)
3. Виклик `AuthService.refresh({})` → `POST /auth/refresh`
   - Refresh token передається автоматично через httpOnly cookie
   - Тіло запиту може бути порожнім — бекенд бере token з cookie (`req.cookies?.refreshToken || dto.refreshToken`)
4. Бекенд:
   - Верифікує refresh token
   - Видаляє старий refresh token з БД (rotation)
   - Генерує новий access token (15 хв)
   - Генерує новий refresh token, зберігає в БД
   - Встановлює новий refresh token як httpOnly cookie
   - Повертає `{ accessToken, refreshToken }`
5. Фронтенд:
   - Оновлює `accessToken` в store
   - Оновлює `OpenAPI.TOKEN = newAccessToken`
   - **Повторює** оригінальний запит, який отримав 401

### Захист від циклів

- Якщо refresh запит сам повертає 401 → refresh token невалідний → повний logout + редірект на `/login`
- Не робити refresh якщо запит, що повернув 401 — це сам `/auth/refresh`
- Не робити паралельні refresh — якщо один refresh вже в процесі, інші запити чекають його результату

### Помилки

| HTTP код | Причина | Дія на фронтенді |
|---|---|---|
| 401 | Refresh token невалідний/протухший/відкликаний | Повний logout, редірект на `/login` |
| 500 | Серверна помилка | Повний logout, редірект на `/login` |

---

## 5. Middleware та Guards

### Auth Middleware

**Файл**: `app/slices/auth/middleware/auth.ts`

**Де застосовується**: всі захищені сторінки (все крім `/login`, `/register`)

**Логіка**:
1. Перевіряє чи `isAuthenticated === true` в auth store
2. Якщо ні — перевіряє чи є `accessToken` в store
3. Якщо є token — намагається `fetchMe()` щоб відновити сесію
4. Якщо `fetchMe()` повертає 401 — намагається `refreshToken()`
5. Якщо refresh успішний — повторює `fetchMe()`
6. Якщо нічого не працює — редірект на `/login`
7. Якщо все OK — пропускає далі

### Guest Middleware

**Файл**: `app/slices/auth/middleware/guest.ts`

**Де застосовується**: `/login`, `/register`

**Логіка**:
1. Перевіряє чи `isAuthenticated === true` в auth store
2. Якщо так — редірект на `/` (home)
3. Якщо ні — пропускає далі (показує форму)

### Застосування

```
definePageMeta({ middleware: ['auth'] })   // для захищених сторінок
definePageMeta({ middleware: ['guest'] })  // для login/register
```

---

## 6. Redirects

| Сценарій | Звідки | Куди | Умова |
|---|---|---|---|
| Успішний логін | `/login` | `/` | Після login + fetchMe |
| Успішна реєстрація | `/register` | `/` | Після register + auto-login |
| Logout | будь-яка | `/login` | Після очищення стану |
| Неавторизований доступ | захищена сторінка | `/login` | Auth middleware, немає валідної сесії |
| Авторизований на login | `/login` | `/` | Guest middleware, вже залогінений |
| Авторизований на register | `/register` | `/` | Guest middleware, вже залогінений |
| Refresh token протух | будь-яка | `/login` | Refresh повернув 401 |

---

## 7. State Persistence

### Проблема
Pinia store живе в памʼяті — при перезавантаженні сторінки `accessToken`, `user`, `isAuthenticated` втрачаються.

### Рішення
Зберігати `accessToken` в `localStorage` (або `sessionStorage`). Refresh token зберігається в httpOnly cookie на бекенді — він не потребує додаткового збереження.

### Відновлення сесії при завантаженні

1. App init (Nuxt plugin або auth middleware):
   - Перевіряє `localStorage` на наявність `accessToken`
   - Якщо є — встановлює `OpenAPI.TOKEN = accessToken`
   - Викликає `fetchMe()` для перевірки валідності
   - Якщо 401 — намагається `refresh()` (cookie відправиться автоматично)
   - Якщо refresh OK — оновлює accessToken, повторює fetchMe
   - Якщо все провалилось — очищує localStorage, стан невалідний

### Що зберігаємо

| Дані | Де | Чому |
|---|---|---|
| `accessToken` | `localStorage` | Потрібен для Bearer header, переживає перезавантаження |
| `refreshToken` | httpOnly cookie (бекенд) | Безпечніше, не доступний з JS |
| `user` | Pinia store (памʼять) | Відновлюється через `fetchMe()`, не потребує збереження |
| `isAuthenticated` | Pinia store (памʼять) | Виводиться з наявності валідного токена |

---

## 8. Error Handling

### Загальна стратегія

- Всі API виклики в store actions обгорнуті в `try/catch`
- Помилки класифікуються за HTTP кодом
- UI показує повідомлення через toast/notification

### Типи помилок

| Категорія | HTTP коди | Дія |
|---|---|---|
| Валідація | 400 | Показати конкретні помилки полів |
| Автентифікація | 401 | Спробувати refresh → якщо не вийшло, logout + редірект |
| Конфлікт | 409 | Показати "Already exists" |
| Не знайдено | 404 | Показати "Not found" |
| Серверна | 500, 502, 503 | Показати "Something went wrong, try again later" |
| Мережа | Network error | Показати "No internet connection" |

### Формат помилки з бекенду

```json
{
  "statusCode": 401,
  "message": "Invalid password",
  "error": "Unauthorized"
}
```

Доступний через `ApiError.body` в згенерованому клієнті.

---

## Архітектура файлів

```
app/slices/auth/
├── AUTH_SPEC.md              ← цей документ
├── nuxt.config.ts
├── stores/
│   └── auth.store.ts         ← Pinia store з auth логікою
├── middleware/
│   ├── auth.ts               ← захист авторизованих сторінок
│   └── guest.ts              ← редірект залогінених з login/register
├── components/
│   ├── login/
│   │   └── Provider.vue      ← форма логіну
│   └── register/
│       └── Provider.vue      ← форма реєстрації
└── pages/
    ├── login.vue
    └── register.vue
```
