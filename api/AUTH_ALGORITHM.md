# Authentication System Algorithm

Language-agnostic specification for implementing user authentication with JWT tokens, refresh tokens, and encryption key management.

---

## Table of Contents

1. [Data Structures](#1-data-structures)
2. [Registration Flow](#2-registration-flow)
3. [Login Flow](#3-login-flow)
4. [Token Refresh Flow](#4-token-refresh-flow)
5. [Logout Flow](#5-logout-flow)
6. [Request Authentication](#6-request-authentication)
7. [Encryption Key Management](#7-encryption-key-management)
8. [Security Constants](#8-security-constants)

---

## 1. Data Structures

### 1.1 User (Database)

```
User {
    id: UUID (primary key)
    email: String (unique)
    passwordHash: String        // bcrypt hash
    encryptionSalt: String      // 16 bytes, hex encoded
    plan: Enum ['FREE', 'PRO']
    createdAt: DateTime
    updatedAt: DateTime
}
```

### 1.2 RefreshToken (Database)

```
RefreshToken {
    id: UUID (primary key)
    userId: UUID (foreign key -> User.id)
    token: String               // 64 random bytes, hex encoded
    expiresAt: DateTime
    createdAt: DateTime
}
```

### 1.3 Access Token Payload (JWT)

```
AccessTokenPayload {
    sub: String                 // User.id
    email: String               // User.email
    encryptionKey: String       // Base64 encoded, 32 bytes (or empty string)
    iat: Number                 // Issued at (Unix timestamp)
    exp: Number                 // Expires at (Unix timestamp)
}
```

### 1.4 Refresh Token Payload (JWT)

```
RefreshTokenPayload {
    sub: String                 // User.id
    tokenId: String             // RefreshToken.id
    iat: Number
    exp: Number
}
```

### 1.5 Encryption Key Cache (Redis)

```
Key: "encryption_key:{userId}"
Value: String (Base64 encoded encryption key)
TTL: 7 days (refreshed on each use)
```

---

## 2. Registration Flow

```
FUNCTION register(email, password):

    // 1. Check if user exists
    existingUser = DB.findUser(email)
    IF existingUser EXISTS:
        THROW ConflictError("User already exists")

    // 2. Generate encryption salt
    encryptionSalt = RANDOM_BYTES(16).toHex()

    // 3. Hash password
    passwordHash = BCRYPT.hash(password, costFactor=10)

    // 4. Create user
    user = DB.createUser({
        id: UUID.generate(),
        email: email,
        passwordHash: passwordHash,
        encryptionSalt: encryptionSalt,
        plan: 'FREE',
        createdAt: NOW(),
        updatedAt: NOW()
    })

    // 5. Return user (without sensitive fields)
    RETURN {
        id: user.id,
        email: user.email,
        plan: user.plan,
        createdAt: user.createdAt
    }
```

---

## 3. Login Flow

```
FUNCTION login(email, password):

    // 1. Find user
    user = DB.findUser(email)
    IF user NOT EXISTS:
        THROW NotFoundError("User not found")

    // 2. Verify password
    isValid = BCRYPT.compare(password, user.passwordHash)
    IF NOT isValid:
        THROW UnauthorizedError("Invalid password")

    // 3. Derive encryption key from password
    encryptionKey = PBKDF2(
        password: password,
        salt: HEX_DECODE(user.encryptionSalt),
        iterations: 100000,
        keyLength: 32,
        hash: 'SHA-256'
    )
    encryptionKeyBase64 = BASE64_ENCODE(encryptionKey)

    // 4. Store encryption key in cache
    REDIS.set(
        key: "encryption_key:" + user.id,
        value: encryptionKeyBase64,
        ttl: 7 * 24 * 60 * 60  // 7 days in seconds
    )

    // 5. Create access token
    accessTokenPayload = {
        sub: user.id,
        email: user.email,
        encryptionKey: encryptionKeyBase64
    }
    accessToken = JWT.sign(
        payload: accessTokenPayload,
        secret: JWT_SECRET,
        expiresIn: "15m"
    )

    // 6. Create refresh token
    refreshToken = generateRefreshToken(user.id)

    // 7. Set refresh token cookie
    SET_COOKIE("refreshToken", refreshToken, {
        httpOnly: true,
        secure: IS_PRODUCTION,
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000,  // 7 days in ms
        path: "/auth"
    })

    // 8. Return response
    RETURN {
        user: { id, email, plan, createdAt, updatedAt },
        accessToken: accessToken,
        refreshToken: refreshToken,
        tokenType: "Bearer"
    }


FUNCTION generateRefreshToken(userId):

    // 1. Clean up expired tokens for this user
    DB.deleteRefreshTokens({
        userId: userId,
        expiresAt: < NOW()
    })

    // 2. Generate random token value
    tokenValue = RANDOM_BYTES(64).toHex()

    // 3. Calculate expiration
    expiresAt = NOW() + 7 days

    // 4. Store in database
    refreshTokenRecord = DB.createRefreshToken({
        id: UUID.generate(),
        userId: userId,
        token: tokenValue,
        expiresAt: expiresAt,
        createdAt: NOW()
    })

    // 5. Create JWT containing token reference
    refreshTokenPayload = {
        sub: userId,
        tokenId: refreshTokenRecord.id
    }

    RETURN JWT.sign(
        payload: refreshTokenPayload,
        secret: REFRESH_TOKEN_SECRET,
        expiresIn: "7d"
    )
```

---

## 4. Token Refresh Flow

```
FUNCTION refresh(refreshTokenJWT):

    // 1. Get refresh token from cookie or body
    refreshToken = REQUEST.cookies["refreshToken"] OR refreshTokenJWT
    IF refreshToken IS EMPTY:
        THROW UnauthorizedError("Refresh token not provided")

    // 2. Verify and decode JWT
    TRY:
        payload = JWT.verify(refreshToken, REFRESH_TOKEN_SECRET)
    CATCH:
        THROW UnauthorizedError("Invalid refresh token")

    // 3. Find token in database
    tokenRecord = DB.findRefreshToken(payload.tokenId)
    IF tokenRecord NOT EXISTS:
        THROW UnauthorizedError("Refresh token not found")

    // 4. Check expiration
    IF tokenRecord.expiresAt < NOW():
        DB.deleteRefreshToken(payload.tokenId)
        THROW UnauthorizedError("Refresh token expired")

    // 5. Verify user match
    IF tokenRecord.userId != payload.sub:
        THROW UnauthorizedError("Token user mismatch")

    // 6. Revoke old refresh token (rotation)
    DB.deleteRefreshToken(payload.tokenId)

    // 7. Get user
    user = DB.findUserById(payload.sub)
    IF user NOT EXISTS:
        THROW NotFoundError("User not found")

    // 8. Check if encryption key exists in cache
    cachedEncryptionKey = REDIS.get("encryption_key:" + user.id)
    hasEncryptionKey = cachedEncryptionKey IS NOT NULL

    // 9. Create new access token
    // NOTE: encryptionKey is empty if not in cache (user needs to re-login)
    accessTokenPayload = {
        sub: user.id,
        email: user.email,
        encryptionKey: ""  // Empty on refresh - use cached key for operations
    }
    accessToken = JWT.sign(
        payload: accessTokenPayload,
        secret: JWT_SECRET,
        expiresIn: "15m"
    )

    // 10. Refresh encryption key TTL if exists
    IF hasEncryptionKey:
        REDIS.expire("encryption_key:" + user.id, 7 * 24 * 60 * 60)

    // 11. Generate new refresh token
    newRefreshToken = generateRefreshToken(user.id)

    // 12. Update cookie
    SET_COOKIE("refreshToken", newRefreshToken, { ... })

    // 13. Return response
    RETURN {
        accessToken: accessToken,
        refreshToken: newRefreshToken,
        hasEncryptionKey: hasEncryptionKey
    }
```

---

## 5. Logout Flow

### 5.1 Single Device Logout

```
FUNCTION logout(refreshTokenJWT):

    // 1. Get refresh token from cookie
    refreshToken = REQUEST.cookies["refreshToken"]

    IF refreshToken IS NOT EMPTY:
        TRY:
            // 2. Decode token
            payload = JWT.verify(refreshToken, REFRESH_TOKEN_SECRET)

            // 3. Revoke token in database
            DB.deleteRefreshToken(payload.tokenId)
        CATCH:
            // Ignore errors - token may be invalid/expired
            PASS

    // 4. Clear cookie
    CLEAR_COOKIE("refreshToken", {
        httpOnly: true,
        secure: IS_PRODUCTION,
        sameSite: "strict",
        path: "/auth"
    })

    RETURN { message: "Logged out successfully" }
```

### 5.2 All Devices Logout

```
FUNCTION logoutAll(userId):

    // 1. Revoke all refresh tokens for user
    DB.deleteAllRefreshTokens(userId)

    // 2. Delete encryption key from cache
    REDIS.delete("encryption_key:" + userId)

    // 3. Clear cookie
    CLEAR_COOKIE("refreshToken", { ... })

    RETURN { message: "Logged out from all devices" }
```

---

## 6. Request Authentication

```
FUNCTION authenticateRequest(request):

    // 1. Check if route is public
    IF route.isPublic:
        RETURN ALLOW

    // 2. Extract token from header
    authHeader = request.headers["Authorization"]
    IF authHeader IS EMPTY:
        THROW UnauthorizedError("Token not provided")

    // 3. Parse Bearer token
    [type, token] = authHeader.split(" ")
    IF type != "Bearer" OR token IS EMPTY:
        THROW UnauthorizedError("Invalid authorization header")

    // 4. Verify JWT
    TRY:
        payload = JWT.verify(token, JWT_SECRET)
    CATCH TokenExpiredError:
        THROW UnauthorizedError("Token expired")
    CATCH:
        THROW UnauthorizedError("Invalid token")

    // 5. Attach user to request
    request.user = {
        sub: payload.sub,       // userId
        email: payload.email,
        encryptionKey: payload.encryptionKey
    }

    RETURN ALLOW
```

---

## 7. Encryption Key Management

### 7.1 Get Encryption Key for Operations

```
FUNCTION getEncryptionKey(userId, accessTokenPayload):

    // 1. Try to get from access token (available right after login)
    IF accessTokenPayload.encryptionKey IS NOT EMPTY:
        RETURN BASE64_DECODE(accessTokenPayload.encryptionKey)

    // 2. Try to get from cache
    cachedKey = REDIS.get("encryption_key:" + userId)
    IF cachedKey IS NOT NULL:
        // Refresh TTL
        REDIS.expire("encryption_key:" + userId, 7 * 24 * 60 * 60)
        RETURN BASE64_DECODE(cachedKey)

    // 3. Key not available - user needs to re-login
    THROW UnauthorizedError("Encryption key expired. Please login again.")
```

### 7.2 Encrypt Data

```
FUNCTION encrypt(plaintext, encryptionKey):

    // 1. Generate random IV
    iv = RANDOM_BYTES(16)

    // 2. Encrypt using AES-256-GCM
    cipher = AES_256_GCM(key: encryptionKey, iv: iv)
    encrypted = cipher.encrypt(plaintext)
    authTag = cipher.getAuthTag()

    // 3. Combine: IV + AuthTag + Ciphertext
    RETURN BASE64_ENCODE(iv + authTag + encrypted)
```

### 7.3 Decrypt Data

```
FUNCTION decrypt(encryptedData, encryptionKey):

    // 1. Decode from base64
    data = BASE64_DECODE(encryptedData)

    // 2. Extract components
    iv = data[0:16]
    authTag = data[16:32]
    ciphertext = data[32:]

    // 3. Decrypt using AES-256-GCM
    decipher = AES_256_GCM(key: encryptionKey, iv: iv, authTag: authTag)
    plaintext = decipher.decrypt(ciphertext)

    RETURN plaintext
```

---

## 8. Security Constants

```
// Token Configuration
JWT_SECRET              = <random 256-bit key>
REFRESH_TOKEN_SECRET    = <random 256-bit key>
ACCESS_TOKEN_EXPIRY     = "15m"     // 15 minutes
REFRESH_TOKEN_EXPIRY    = "7d"      // 7 days

// Password Hashing
BCRYPT_COST_FACTOR      = 10

// Key Derivation (PBKDF2)
PBKDF2_ITERATIONS       = 100000
PBKDF2_KEY_LENGTH       = 32        // bytes (256 bits)
PBKDF2_HASH             = "SHA-256"

// Encryption (AES-256-GCM)
AES_KEY_LENGTH          = 32        // bytes
AES_IV_LENGTH           = 16        // bytes
AES_AUTH_TAG_LENGTH     = 16        // bytes

// Cache Configuration
ENCRYPTION_KEY_TTL      = 604800    // 7 days in seconds

// Cookie Configuration
COOKIE_MAX_AGE          = 604800000 // 7 days in milliseconds
COOKIE_PATH             = "/auth"
COOKIE_SAME_SITE        = "strict"
COOKIE_HTTP_ONLY        = true
COOKIE_SECURE           = true      // in production
```

---

## Flow Diagrams

### Complete Authentication Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                         REGISTRATION                             │
├─────────────────────────────────────────────────────────────────┤
│  Client                           Server                         │
│    │                                │                            │
│    │─── POST /auth/register ───────>│                            │
│    │    {email, password}           │                            │
│    │                                │── Check email unique       │
│    │                                │── Generate salt            │
│    │                                │── Hash password (bcrypt)   │
│    │                                │── Create user in DB        │
│    │<── 201 {user} ─────────────────│                            │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                            LOGIN                                 │
├─────────────────────────────────────────────────────────────────┤
│  Client                           Server                         │
│    │                                │                            │
│    │─── POST /auth/login ──────────>│                            │
│    │    {email, password}           │                            │
│    │                                │── Find user                │
│    │                                │── Verify password          │
│    │                                │── Derive encryption key    │
│    │                                │── Store key in Redis       │
│    │                                │── Create access token      │
│    │                                │── Create refresh token     │
│    │                                │── Store refresh in DB      │
│    │<── 200 {tokens} ───────────────│                            │
│    │    + Set-Cookie: refreshToken  │                            │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                         API REQUEST                              │
├─────────────────────────────────────────────────────────────────┤
│  Client                           Server                         │
│    │                                │                            │
│    │─── GET /api/resource ─────────>│                            │
│    │    Authorization: Bearer {AT}  │                            │
│    │                                │── Extract token            │
│    │                                │── Verify JWT signature     │
│    │                                │── Check expiration         │
│    │                                │── Attach user to request   │
│    │<── 200 {data} ─────────────────│                            │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                        TOKEN REFRESH                             │
├─────────────────────────────────────────────────────────────────┤
│  Client                           Server                         │
│    │                                │                            │
│    │─── POST /auth/refresh ────────>│                            │
│    │    Cookie: refreshToken        │                            │
│    │                                │── Verify refresh JWT       │
│    │                                │── Find token in DB         │
│    │                                │── Check expiration         │
│    │                                │── Revoke old token         │
│    │                                │── Create new access token  │
│    │                                │── Create new refresh token │
│    │                                │── Refresh Redis TTL        │
│    │<── 200 {tokens} ───────────────│                            │
│    │    + Set-Cookie: refreshToken  │                            │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                           LOGOUT                                 │
├─────────────────────────────────────────────────────────────────┤
│  Client                           Server                         │
│    │                                │                            │
│    │─── POST /auth/logout ─────────>│                            │
│    │    Authorization: Bearer {AT}  │                            │
│    │    Cookie: refreshToken        │                            │
│    │                                │── Revoke refresh token     │
│    │                                │── Clear cookie             │
│    │<── 200 {message} ──────────────│                            │
│    │    + Clear-Cookie              │                            │
└─────────────────────────────────────────────────────────────────┘
```

### Token Lifecycle

```
Login
  │
  ├──> Access Token (15 min)
  │      │
  │      │── Used for API requests
  │      │── Contains encryptionKey (only on login)
  │      │
  │      └── Expires ──> Refresh needed
  │
  └──> Refresh Token (7 days)
         │
         ├── Stored in httpOnly cookie
         ├── Reference stored in DB
         │
         ├── On refresh:
         │     ├── Old token revoked
         │     ├── New tokens issued
         │     └── Redis TTL refreshed
         │
         └── Expires ──> Full re-login needed
```

### Encryption Key Lifecycle

```
Login (with password)
  │
  ├──> Derive key using PBKDF2
  │
  ├──> Store in Redis (TTL: 7 days)
  │
  └──> Include in Access Token
        │
        ├── Available for encryption operations
        │
        └── On token refresh:
              │
              ├── NOT included in new access token
              │
              └── Retrieved from Redis when needed
                    │
                    ├── TTL refreshed on access
                    │
                    └── If expired ──> Re-login required
```

---

## Implementation Checklist

- [ ] User registration with password hashing
- [ ] User login with JWT generation
- [ ] Refresh token rotation
- [ ] Secure cookie handling
- [ ] Request authentication middleware
- [ ] Encryption key derivation (PBKDF2)
- [ ] Encryption key caching (Redis)
- [ ] Data encryption (AES-256-GCM)
- [ ] Logout (single device)
- [ ] Logout (all devices)
- [ ] Token expiration handling
- [ ] Error handling and security responses
