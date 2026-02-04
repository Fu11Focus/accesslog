# JWT Implementation Guide

## Огляд архітектури

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Client    │────▶│  Auth API   │────▶│  Database   │
│             │     │             │     │             │
│ Bearer token│◀────│ JWT + Key   │◀────│ User + Salt │
└─────────────┘     └─────────────┘     └─────────────┘
                           │
                           ▼
                    ┌─────────────┐
                    │ Protected   │
                    │ Resources   │
                    │ (Access)    │
                    └─────────────┘
```

## Крок 1: Встановлення залежностей

```bash
npm install @nestjs/jwt @nestjs/passport passport passport-jwt
npm install -D @types/passport-jwt
```

---

## Крок 2: Змінні середовища

Додай в `.env`:

```env
JWT_SECRET=your-super-secret-key-at-least-32-characters-long
JWT_EXPIRES_IN=24h
```

Додай в `.env.example`:

```env
JWT_SECRET=
JWT_EXPIRES_IN=24h
```

---

## Крок 3: Структура файлів

Створи наступні файли:

```
src/slices/users/auth/
├── auth.module.ts              # оновити
├── auth.controller.ts          # створити
├── auth.guard.ts               # створити
├── public.decorator.ts         # створити
├── user.decorator.ts           # створити
├── domain/
│   ├── auth.gateway.ts         # існує (інтерфейс)
│   └── jwt-payload.interface.ts # створити
└── data/
    └── auth.gateway.ts         # оновити
```

---

## Крок 4: JWT Payload Interface

**Файл:** `src/slices/users/auth/domain/jwt-payload.interface.ts`

```typescript
export interface IJwtPayload {
  sub: string;           // user.id
  email: string;
  encryptionKey: string; // Base64 encoded key для шифрування Access даних
  iat?: number;          // issued at (автоматично)
  exp?: number;          // expires at (автоматично)
}
```

---

## Крок 5: Public Decorator

**Файл:** `src/slices/users/auth/public.decorator.ts`

```typescript
import { SetMetadata } from '@nestjs/common';

export const IS_PUBLIC_KEY = 'isPublic';
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);
```

---

## Крок 6: User Decorator

**Файл:** `src/slices/users/auth/user.decorator.ts`

```typescript
import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { IJwtPayload } from './domain/jwt-payload.interface';

export const CurrentUser = createParamDecorator(
  (data: keyof IJwtPayload | undefined, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    const user = request.user as IJwtPayload;

    // Якщо вказано конкретне поле, повернути його
    if (data) {
      return user[data];
    }

    return user;
  },
);
```

---

## Крок 7: Auth Guard

**Файл:** `src/slices/users/auth/auth.guard.ts`

```typescript
import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { IS_PUBLIC_KEY } from './public.decorator';
import { IJwtPayload } from './domain/jwt-payload.interface';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private jwtService: JwtService,
    private reflector: Reflector,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Перевірка чи маршрут публічний
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (isPublic) {
      return true;
    }

    const request = context.switchToHttp().getRequest<Request>();
    const token = this.extractTokenFromHeader(request);

    if (!token) {
      throw new UnauthorizedException('Token not provided');
    }

    try {
      const payload = await this.jwtService.verifyAsync<IJwtPayload>(token, {
        secret: process.env.JWT_SECRET,
      });

      // Додаємо payload до request для доступу через @CurrentUser()
      request['user'] = payload;
    } catch (error) {
      throw new UnauthorizedException('Invalid or expired token');
    }

    return true;
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const authorization = request.headers.authorization;
    if (!authorization) return undefined;

    const [type, token] = authorization.split(' ');
    return type === 'Bearer' ? token : undefined;
  }
}
```

---

## Крок 8: Auth Gateway (оновлення)

**Файл:** `src/slices/users/auth/data/auth.gateway.ts`

```typescript
import { User } from '@prisma/client';
import { IAuthGateway } from '../domain/auth.gateway';
import { PrismaService } from '#prisma/prisma.service';
import { EncryptionService } from '#core/domain/services/encryption.service';
import { JwtService } from '@nestjs/jwt';
import { IJwtPayload } from '../domain/jwt-payload.interface';
import * as bcrypt from 'bcrypt';

export interface LoginResult {
  user: User;
  accessToken: string;
}

export class AuthGateway implements IAuthGateway {
  constructor(
    private readonly prisma: PrismaService,
    private readonly encryptionService: EncryptionService,
    private readonly jwtService: JwtService,
  ) {}

  async login(email: string, password: string): Promise<LoginResult> {
    // 1. Знайти користувача
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) {
      throw new Error('User not found');
    }

    // 2. Перевірити пароль
    const isPasswordValid = bcrypt.compareSync(password, user.passwordHash);
    if (!isPasswordValid) {
      throw new Error('Invalid password');
    }

    // 3. Вивести encryption key з пароля
    const encryptionKey = this.encryptionService.deriveKey(
      password,
      user.encryptionSalt,
    );

    // 4. Створити JWT payload
    const payload: IJwtPayload = {
      sub: user.id,
      email: user.email,
      encryptionKey: encryptionKey.toString('base64'),
    };

    // 5. Підписати токен
    const accessToken = await this.jwtService.signAsync(payload, {
      secret: process.env.JWT_SECRET,
      expiresIn: process.env.JWT_EXPIRES_IN || '24h',
    });

    return { user, accessToken };
  }

  async register(email: string, password: string): Promise<User> {
    // Перевірити чи користувач вже існує
    const existingUser = await this.prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      throw new Error('User already exists');
    }

    const encryptionSalt = this.encryptionService.generateSalt();
    const passwordHash = bcrypt.hashSync(password, 10);

    const user = await this.prisma.user.create({
      data: { email, passwordHash, encryptionSalt },
    });

    return user;
  }

  async logout(): Promise<void> {
    // JWT stateless - logout відбувається на клієнті (видалення токена)
    // Опціонально: можна додати токен в blacklist (Redis)
  }

  async verifyPassword(userId: string, password: string): Promise<boolean> {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) return false;
    return bcrypt.compareSync(password, user.passwordHash);
  }
}
```

---

## Крок 9: Auth Controller

**Файл:** `src/slices/users/auth/auth.controller.ts`

```typescript
import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  Get,
  BadRequestException,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth } from '@nestjs/swagger';
import { AuthGateway } from './data/auth.gateway';
import { Public } from './public.decorator';
import { CurrentUser } from './user.decorator';
import { IJwtPayload } from './domain/jwt-payload.interface';

// DTOs
class LoginDto {
  email: string;
  password: string;
}

class RegisterDto {
  email: string;
  password: string;
}

class LoginResponseDto {
  accessToken: string;
  tokenType: string;
  user: {
    id: string;
    email: string;
  };
}

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authGateway: AuthGateway) {}

  @Public()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Login with email and password' })
  async login(@Body() dto: LoginDto): Promise<LoginResponseDto> {
    try {
      const result = await this.authGateway.login(dto.email, dto.password);

      return {
        accessToken: result.accessToken,
        tokenType: 'Bearer',
        user: {
          id: result.user.id,
          email: result.user.email,
        },
      };
    } catch (error) {
      throw new BadRequestException(error.message);
    }
  }

  @Public()
  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Register new user' })
  async register(@Body() dto: RegisterDto) {
    try {
      const user = await this.authGateway.register(dto.email, dto.password);

      return {
        message: 'User created successfully',
        user: {
          id: user.id,
          email: user.email,
        },
      };
    } catch (error) {
      throw new BadRequestException(error.message);
    }
  }

  @Get('me')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get current user info' })
  async me(@CurrentUser() user: IJwtPayload) {
    return {
      id: user.sub,
      email: user.email,
      // НЕ повертаємо encryptionKey клієнту!
    };
  }
}
```

---

## Крок 10: Auth Module

**Файл:** `src/slices/users/auth/auth.module.ts`

```typescript
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { APP_GUARD } from '@nestjs/core';
import { AuthController } from './auth.controller';
import { AuthGateway } from './data/auth.gateway';
import { AuthGuard } from './auth.guard';
import { PrismaModule } from '#prisma/prisma.module';
// import { EncryptionModule } from '#core/encryption.module'; // якщо є

@Module({
  imports: [
    PrismaModule,
    JwtModule.register({
      global: true,
      secret: process.env.JWT_SECRET,
      signOptions: { expiresIn: process.env.JWT_EXPIRES_IN || '24h' },
    }),
  ],
  controllers: [AuthController],
  providers: [
    AuthGateway,
    // Глобальний guard - всі маршрути захищені за замовчуванням
    {
      provide: APP_GUARD,
      useClass: AuthGuard,
    },
  ],
  exports: [AuthGateway],
})
export class AuthModule {}
```

---

## Крок 11: Використання в інших контролерах

### Захищений ендпоінт (за замовчуванням):

```typescript
@Controller('accesses')
export class AccessController {
  @Get()
  @ApiBearerAuth()
  async getAll(@CurrentUser() user: IJwtPayload) {
    // user.sub - ID користувача
    // user.encryptionKey - ключ для дешифрування
    const key = Buffer.from(user.encryptionKey, 'base64');
    // використовуй key для decrypt
  }
}
```

### Публічний ендпоінт:

```typescript
@Public()
@Get('health')
healthCheck() {
  return { status: 'ok' };
}
```

---

## Крок 12: Шифрування/дешифрування Access даних

**Приклад використання в Access сервісі:**

```typescript
@Injectable()
export class AccessService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly encryptionService: EncryptionService,
  ) {}

  async create(
    userId: string,
    encryptionKey: string, // з JWT payload
    data: CreateAccessDto,
  ) {
    const key = Buffer.from(encryptionKey, 'base64');

    // Шифруємо пароль перед збереженням
    const passwordEncrypted = this.encryptionService.encrypt(
      data.password,
      key,
    );

    return this.prisma.access.create({
      data: {
        ...data,
        passwordEncrypted,
        password: undefined, // не зберігаємо plain password
      },
    });
  }

  async findOne(
    id: string,
    userId: string,
    encryptionKey: string,
  ) {
    const access = await this.prisma.access.findUnique({
      where: { id },
    });

    const key = Buffer.from(encryptionKey, 'base64');

    // Дешифруємо пароль при читанні
    const password = this.encryptionService.decrypt(
      access.passwordEncrypted,
      key,
    );

    return {
      ...access,
      password, // повертаємо розшифрований
    };
  }
}
```

---

## Тестування

### Register:

```bash
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "securepassword123"}'
```

### Login:

```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "securepassword123"}'

# Response:
# {
#   "accessToken": "eyJhbGciOiJIUzI1NiIs...",
#   "tokenType": "Bearer",
#   "user": { "id": "...", "email": "test@example.com" }
# }
```

### Protected endpoint:

```bash
curl http://localhost:3000/auth/me \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..."
```

---

## Безпека

| Аспект | Рекомендація |
|--------|--------------|
| JWT_SECRET | Мінімум 32 символи, криптографічно випадкові |
| Token expiration | 15-60 хв для високої безпеки, 24h для зручності |
| HTTPS | Обов'язково в production |
| encryptionKey в JWT | Безпечно, бо JWT підписаний і не декодується без secret |
| Зберігання на клієнті | httpOnly cookie (найбезпечніше) або memory (не localStorage) |

---

## Refresh Tokens

Refresh tokens дозволяють продовжувати сесію без повторного введення пароля.

### Архітектура

```
┌─────────────┐                              ┌─────────────┐
│   Client    │                              │   Server    │
└─────────────┘                              └─────────────┘
       │                                            │
       │  1. Login (email, password)                │
       │ ──────────────────────────────────────────▶│
       │                                            │
       │  2. Return accessToken + refreshToken      │
       │ ◀──────────────────────────────────────────│
       │                                            │
       │  3. API calls with accessToken             │
       │ ──────────────────────────────────────────▶│
       │                                            │
       │  4. accessToken expires (401)              │
       │ ◀──────────────────────────────────────────│
       │                                            │
       │  5. POST /auth/refresh (refreshToken)      │
       │ ──────────────────────────────────────────▶│
       │                                            │
       │  6. Return new accessToken + refreshToken  │
       │ ◀──────────────────────────────────────────│
       │                                            │
```

### Різниця між токенами

| Аспект | Access Token | Refresh Token |
|--------|--------------|---------------|
| Термін дії | 15 хв - 1 год | 7-30 днів |
| Містить | user data + encryptionKey | тільки tokenId |
| Зберігання | Memory / httpOnly cookie | httpOnly cookie (обов'язково) |
| Використання | Authorization header | Тільки для /auth/refresh |
| Відкликання | Неможливо (stateless) | Можливо (зберігається в БД) |

---

### Крок 1: Оновити схему Prisma

Додай модель для зберігання refresh tokens:

**Файл:** `src/slices/users/auth/auth.prisma`

```prisma
model RefreshToken {
  id        String   @id @default(uuid())
  userId    String
  token     String   @unique
  expiresAt DateTime
  createdAt DateTime @default(now())

  user User @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@index([userId])
  @@index([token])
}
```

Оновити модель User:

```prisma
model User {
  // ... existing fields

  refreshTokens RefreshToken[]
}
```

Запустити міграцію:

```bash
npm run prisma:migrate
```

---

### Крок 2: Оновити змінні середовища

```env
JWT_SECRET=your-access-token-secret-32-chars
JWT_EXPIRES_IN=15m

REFRESH_TOKEN_SECRET=your-refresh-token-secret-different-from-jwt
REFRESH_TOKEN_EXPIRES_IN=7d
```

---

### Крок 3: Створити Refresh Token Service

**Файл:** `src/slices/users/auth/data/refresh-token.service.ts`

```typescript
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '#prisma/prisma.service';
import * as crypto from 'crypto';

interface RefreshTokenPayload {
  sub: string;      // user id
  tokenId: string;  // refresh token id in DB
}

@Injectable()
export class RefreshTokenService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
  ) {}

  async generateRefreshToken(userId: string): Promise<string> {
    // Видалити старі токени користувача (опціонально - обмежити кількість сесій)
    await this.prisma.refreshToken.deleteMany({
      where: {
        userId,
        expiresAt: { lt: new Date() }, // видалити тільки expired
      },
    });

    // Створити унікальний токен
    const tokenValue = crypto.randomBytes(64).toString('hex');

    // Розрахувати дату закінчення (7 днів)
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    // Зберегти в БД
    const refreshToken = await this.prisma.refreshToken.create({
      data: {
        userId,
        token: tokenValue,
        expiresAt,
      },
    });

    // Створити JWT з refresh token payload
    const payload: RefreshTokenPayload = {
      sub: userId,
      tokenId: refreshToken.id,
    };

    return this.jwtService.signAsync(payload, {
      secret: process.env.REFRESH_TOKEN_SECRET,
      expiresIn: '7d',
    });
  }

  async verifyRefreshToken(token: string): Promise<{ userId: string; tokenId: string }> {
    try {
      // Верифікувати JWT
      const payload = await this.jwtService.verifyAsync<RefreshTokenPayload>(token, {
        secret: process.env.REFRESH_TOKEN_SECRET,
      });

      // Перевірити чи токен існує в БД і не expired
      const refreshToken = await this.prisma.refreshToken.findUnique({
        where: { id: payload.tokenId },
      });

      if (!refreshToken) {
        throw new UnauthorizedException('Refresh token not found');
      }

      if (refreshToken.expiresAt < new Date()) {
        // Видалити expired токен
        await this.prisma.refreshToken.delete({ where: { id: payload.tokenId } });
        throw new UnauthorizedException('Refresh token expired');
      }

      if (refreshToken.userId !== payload.sub) {
        throw new UnauthorizedException('Token user mismatch');
      }

      return { userId: payload.sub, tokenId: payload.tokenId };
    } catch (error) {
      if (error instanceof UnauthorizedException) throw error;
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  async revokeRefreshToken(tokenId: string): Promise<void> {
    await this.prisma.refreshToken.delete({
      where: { id: tokenId },
    }).catch(() => {
      // Ігноруємо якщо токен вже видалений
    });
  }

  async revokeAllUserTokens(userId: string): Promise<void> {
    await this.prisma.refreshToken.deleteMany({
      where: { userId },
    });
  }
}
```

---

### Крок 4: Оновити Auth Gateway

**Файл:** `src/slices/users/auth/data/auth.gateway.ts`

```typescript
import { Injectable, NotFoundException, UnauthorizedException, ConflictException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '#prisma/prisma.service';
import { EncryptionService } from '#core/domain/services/encryption.service';
import { RefreshTokenService } from './refresh-token.service';
import { IJwtPayload } from '../domain/interfaces/jwt-payload.interface';
import { AuthMapper } from './auth.mapper';
import * as bcrypt from 'bcrypt';

export interface ILoginResult {
  user: IUser;
  accessToken: string;
  refreshToken: string;
}

export interface IRefreshResult {
  accessToken: string;
  refreshToken: string;
}

@Injectable()
export class AuthGateway {
  constructor(
    private readonly prisma: PrismaService,
    private readonly encryptionService: EncryptionService,
    private readonly jwtService: JwtService,
    private readonly refreshTokenService: RefreshTokenService,
    private readonly authMapper: AuthMapper,
  ) {}

  async login(email: string, password: string): Promise<ILoginResult> {
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) {
      throw new NotFoundException('User not found');
    }

    const isPasswordValid = bcrypt.compareSync(password, user.passwordHash);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid password');
    }

    // Генерувати access token
    const encryptionKey = this.encryptionService.deriveKey(password, user.encryptionSalt);
    const payload: IJwtPayload = {
      sub: user.id,
      email: user.email,
      encryptionKey: encryptionKey.toString('base64'),
    };

    const accessToken = await this.jwtService.signAsync(
      { ...payload },
      {
        secret: process.env.JWT_SECRET,
        expiresIn: process.env.JWT_EXPIRES_IN || '15m',
      },
    );

    // Генерувати refresh token
    const refreshToken = await this.refreshTokenService.generateRefreshToken(user.id);

    return {
      user: this.authMapper.toUserDomain(user),
      accessToken,
      refreshToken,
    };
  }

  async refresh(refreshToken: string, password?: string): Promise<IRefreshResult> {
    // Верифікувати refresh token
    const { userId, tokenId } = await this.refreshTokenService.verifyRefreshToken(refreshToken);

    // Знайти користувача
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Відкликати старий refresh token (rotation)
    await this.refreshTokenService.revokeRefreshToken(tokenId);

    // Генерувати новий access token
    // ВАЖЛИВО: encryptionKey потребує пароля!
    // Варіант 1: Зберігати encryptionKey в refresh token (менш безпечно)
    // Варіант 2: Вимагати пароль при refresh (незручно)
    // Варіант 3: Кешувати encryptionKey на сервері (Redis)

    // Для простоти - генеруємо токен без encryptionKey
    // Клієнт повинен зробити повторний login якщо потрібен encryptionKey
    const payload: IJwtPayload = {
      sub: user.id,
      email: user.email,
      encryptionKey: '', // Порожній - клієнт повинен перелогінитись для шифрування
    };

    const accessToken = await this.jwtService.signAsync(
      { ...payload },
      {
        secret: process.env.JWT_SECRET,
        expiresIn: process.env.JWT_EXPIRES_IN || '15m',
      },
    );

    // Генерувати новий refresh token (rotation)
    const newRefreshToken = await this.refreshTokenService.generateRefreshToken(user.id);

    return {
      accessToken,
      refreshToken: newRefreshToken,
    };
  }

  async logout(refreshToken: string): Promise<void> {
    try {
      const { tokenId } = await this.refreshTokenService.verifyRefreshToken(refreshToken);
      await this.refreshTokenService.revokeRefreshToken(tokenId);
    } catch {
      // Ігноруємо помилки - токен вже недійсний
    }
  }

  async logoutAll(userId: string): Promise<void> {
    await this.refreshTokenService.revokeAllUserTokens(userId);
  }
}
```

---

### Крок 5: Оновити Auth Controller

**Файл:** `src/slices/users/auth/auth.controller.ts`

```typescript
import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  Get,
  Res,
  Req,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth } from '@nestjs/swagger';
import { Response, Request } from 'express';
import { AuthGateway } from './data/auth.gateway';
import { Public } from './public.decorator';
import { CurrentUser } from './user.decorator';
import { IJwtPayload } from './domain/interfaces/jwt-payload.interface';

class AuthDto {
  email: string;
  password: string;
}

class RefreshDto {
  refreshToken?: string; // Опціонально, якщо використовуємо cookies
}

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authGateway: AuthGateway) {}

  @Public()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Login and receive tokens' })
  async login(
    @Body() dto: AuthDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.authGateway.login(dto.email, dto.password);

    // Встановити refresh token в httpOnly cookie
    this.setRefreshTokenCookie(res, result.refreshToken);

    return {
      accessToken: result.accessToken,
      tokenType: 'Bearer',
      expiresIn: 900, // 15 хвилин в секундах
      user: result.user,
    };
  }

  @Public()
  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Register new user' })
  async register(@Body() dto: AuthDto) {
    const user = await this.authGateway.register(dto.email, dto.password);
    return {
      message: 'User created successfully',
      user,
    };
  }

  @Public()
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Refresh access token' })
  async refresh(
    @Req() req: Request,
    @Body() dto: RefreshDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    // Отримати refresh token з cookie або body
    const refreshToken = req.cookies?.refreshToken || dto.refreshToken;

    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token not provided');
    }

    const result = await this.authGateway.refresh(refreshToken);

    // Оновити refresh token cookie
    this.setRefreshTokenCookie(res, result.refreshToken);

    return {
      accessToken: result.accessToken,
      tokenType: 'Bearer',
      expiresIn: 900,
    };
  }

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Logout and revoke refresh token' })
  async logout(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const refreshToken = req.cookies?.refreshToken;

    if (refreshToken) {
      await this.authGateway.logout(refreshToken);
    }

    // Очистити cookie
    this.clearRefreshTokenCookie(res);

    return { message: 'Logged out successfully' };
  }

  @Post('logout-all')
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Logout from all devices' })
  async logoutAll(
    @CurrentUser() user: IJwtPayload,
    @Res({ passthrough: true }) res: Response,
  ) {
    await this.authGateway.logoutAll(user.sub);
    this.clearRefreshTokenCookie(res);

    return { message: 'Logged out from all devices' };
  }

  @Get('me')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get current user' })
  async me(@CurrentUser() user: IJwtPayload) {
    return {
      id: user.sub,
      email: user.email,
    };
  }

  // Helper methods
  private setRefreshTokenCookie(res: Response, token: string) {
    res.cookie('refreshToken', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 днів
      path: '/auth', // Тільки для auth endpoints
    });
  }

  private clearRefreshTokenCookie(res: Response) {
    res.clearCookie('refreshToken', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/auth',
    });
  }
}
```

---

### Крок 6: Оновити Auth Module

**Файл:** `src/slices/users/auth/auth.module.ts`

```typescript
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { APP_GUARD } from '@nestjs/core';
import { AuthController } from './auth.controller';
import { AuthGateway } from './data/auth.gateway';
import { AuthMapper } from './data/auth.mapper';
import { RefreshTokenService } from './data/refresh-token.service';
import { AuthGuard } from './auth.guard';
import { PrismaModule } from '#prisma/prisma.module';
import { EncryptionService } from '#core/domain/services/encryption.service';

@Module({
  imports: [
    PrismaModule,
    JwtModule.register({
      global: true,
      secret: process.env.JWT_SECRET,
      signOptions: { expiresIn: process.env.JWT_EXPIRES_IN || '15m' },
    }),
  ],
  controllers: [AuthController],
  providers: [
    AuthGateway,
    AuthMapper,
    RefreshTokenService,
    EncryptionService,
    {
      provide: APP_GUARD,
      useClass: AuthGuard,
    },
  ],
  exports: [AuthGateway],
})
export class AuthModule {}
```

---

### Крок 7: Додати cookie-parser

```bash
npm install cookie-parser
npm install -D @types/cookie-parser
```

**Файл:** `src/main.ts`

```typescript
import 'dotenv/config';
import * as cookieParser from 'cookie-parser';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.use(cookieParser());

  // ... swagger setup

  await app.listen(process.env.PORT ?? 3333);
}
bootstrap();
```

---

### Використання на клієнті

**Login:**
```typescript
const response = await fetch('/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include', // Важливо для cookies!
  body: JSON.stringify({ email, password }),
});

const { accessToken } = await response.json();
// Зберегти accessToken в memory (не localStorage!)
```

**API запити:**
```typescript
const response = await fetch('/api/accesses', {
  headers: { 'Authorization': `Bearer ${accessToken}` },
  credentials: 'include',
});

if (response.status === 401) {
  // Access token expired - refresh
  const refreshResponse = await fetch('/auth/refresh', {
    method: 'POST',
    credentials: 'include', // Cookie автоматично відправиться
  });

  if (refreshResponse.ok) {
    const { accessToken: newToken } = await refreshResponse.json();
    // Повторити оригінальний запит з новим токеном
  } else {
    // Redirect to login
  }
}
```

---

### Безпека Refresh Tokens

| Аспект | Рекомендація |
|--------|--------------|
| Зберігання | Тільки httpOnly cookie |
| Rotation | Видаляти старий токен при кожному refresh |
| Термін дії | 7-30 днів максимум |
| Відкликання | Logout видаляє токен з БД |
| Обмеження сесій | Опціонально - максимум 5 активних токенів |
| Виявлення reuse | Якщо токен використаний двічі - відкликати всі токени користувача |

---

### Важливо: encryptionKey при Refresh

При refresh ми **не можемо** відновити `encryptionKey` без пароля. Варіанти:

1. **Порожній encryptionKey** - клієнт повинен перелогінитись для операцій шифрування
2. **Кешувати в Redis** - зберігати encryptionKey в Redis з TTL рівним refresh token
3. **Шифрувати encryptionKey** - зберігати зашифрований ключ в refresh token record

Рекомендація: Варіант 1 (найпростіший) або Варіант 2 (найзручніший для UX).

---

## Redis для збереження encryptionKey

Redis дозволяє зберігати `encryptionKey` між refresh токенами, щоб користувач міг продовжувати шифрувати/дешифрувати дані без повторного логіну.

### Архітектура з Redis

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Client    │────▶│  Auth API   │────▶│  PostgreSQL │
│             │     │             │     │  (Users)    │
│ accessToken │◀────│             │     └─────────────┘
└─────────────┘     │             │
                    │             │     ┌─────────────┐
                    │             │────▶│    Redis    │
                    │             │     │(encryptKey) │
                    └─────────────┘     └─────────────┘

Login:
1. Користувач логіниться з паролем
2. Генерується encryptionKey з пароля
3. encryptionKey зберігається в Redis (TTL = 7 днів)
4. accessToken містить encryptionKey

Refresh:
1. Клієнт відправляє refreshToken
2. Сервер бере encryptionKey з Redis
3. Генерується новий accessToken з encryptionKey
4. TTL в Redis продовжується
```

### Крок 1: Встановити залежності

```bash
npm install @nestjs/cache-manager cache-manager cache-manager-redis-store redis
npm install -D @types/cache-manager-redis-store
```

### Крок 2: Додати Redis конфігурацію

**Файл:** `.env`

```env
# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_TTL=604800  # 7 днів в секундах

# JWT
JWT_SECRET=your-access-token-secret-32-chars
JWT_EXPIRES_IN=15m

REFRESH_TOKEN_SECRET=your-refresh-token-secret-different-from-jwt
REFRESH_TOKEN_EXPIRES_IN=7d
```

### Крок 3: Налаштувати Redis Module

**Файл:** `src/slices/core/redis/redis.module.ts`

```typescript
import { Module } from '@nestjs/common';
import { CacheModule } from '@nestjs/cache-manager';
import { redisStore } from 'cache-manager-redis-store';

@Module({
  imports: [
    CacheModule.registerAsync({
      isGlobal: true,
      useFactory: async () => ({
        store: await redisStore({
          socket: {
            host: process.env.REDIS_HOST || 'localhost',
            port: parseInt(process.env.REDIS_PORT || '6379'),
          },
          password: process.env.REDIS_PASSWORD || undefined,
          ttl: parseInt(process.env.REDIS_TTL || '604800'), // 7 днів
        }),
      }),
    }),
  ],
})
export class RedisModule {}
```

### Крок 4: Створити Encryption Key Cache Service

**Файл:** `src/slices/users/auth/data/encryption-key-cache.service.ts`

```typescript
import { Injectable, Inject } from '@nestjs/common';
import { CACHE_MANAGER, Cache } from '@nestjs/cache-manager';

@Injectable()
export class EncryptionKeyCacheService {
  private readonly KEY_PREFIX = 'encryption:';
  private readonly DEFAULT_TTL = 7 * 24 * 60 * 60; // 7 днів в секундах

  constructor(@Inject(CACHE_MANAGER) private cacheManager: Cache) {}

  /**
   * Зберегти encryptionKey при логіні
   */
  async set(userId: string, encryptionKey: string): Promise<void> {
    const key = this.KEY_PREFIX + userId;
    await this.cacheManager.set(key, encryptionKey, this.DEFAULT_TTL);
  }

  /**
   * Отримати encryptionKey при refresh
   */
  async get(userId: string): Promise<string | null> {
    const key = this.KEY_PREFIX + userId;
    const value = await this.cacheManager.get<string>(key);
    return value || null;
  }

  /**
   * Продовжити TTL при кожному refresh
   */
  async refresh(userId: string): Promise<boolean> {
    const key = this.KEY_PREFIX + userId;
    const value = await this.cacheManager.get<string>(key);

    if (value) {
      // Перезаписати з новим TTL
      await this.cacheManager.set(key, value, this.DEFAULT_TTL);
      return true;
    }
    return false;
  }

  /**
   * Видалити при logout
   */
  async delete(userId: string): Promise<void> {
    const key = this.KEY_PREFIX + userId;
    await this.cacheManager.del(key);
  }

  /**
   * Перевірити чи існує ключ
   */
  async exists(userId: string): Promise<boolean> {
    const value = await this.get(userId);
    return value !== null;
  }
}
```

### Крок 5: Оновити Auth Gateway з Redis

**Файл:** `src/slices/users/auth/data/auth.gateway.ts`

```typescript
import { Injectable, NotFoundException, UnauthorizedException, ConflictException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '#prisma/prisma.service';
import { EncryptionService } from '#core/domain/services/encryption.service';
import { RefreshTokenService } from './refresh-token.service';
import { EncryptionKeyCacheService } from './encryption-key-cache.service';
import { IJwtPayload } from '../domain/interfaces/jwt-payload.interface';
import { AuthMapper } from './auth.mapper';
import * as bcrypt from 'bcrypt';

export interface ILoginResult {
  user: IUser;
  accessToken: string;
  refreshToken: string;
}

export interface IRefreshResult {
  accessToken: string;
  refreshToken: string;
  hasEncryptionKey: boolean; // Клієнт знає чи може шифрувати
}

@Injectable()
export class AuthGateway {
  constructor(
    private readonly prisma: PrismaService,
    private readonly encryptionService: EncryptionService,
    private readonly jwtService: JwtService,
    private readonly refreshTokenService: RefreshTokenService,
    private readonly encryptionKeyCache: EncryptionKeyCacheService,
    private readonly authMapper: AuthMapper,
  ) {}

  async login(email: string, password: string): Promise<ILoginResult> {
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) {
      throw new NotFoundException('User not found');
    }

    const isPasswordValid = bcrypt.compareSync(password, user.passwordHash);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid password');
    }

    // Генерувати encryption key з пароля
    const encryptionKey = this.encryptionService.deriveKey(password, user.encryptionSalt);
    const encryptionKeyBase64 = encryptionKey.toString('base64');

    // ⭐ Зберегти encryptionKey в Redis
    await this.encryptionKeyCache.set(user.id, encryptionKeyBase64);

    // Генерувати access token
    const payload: IJwtPayload = {
      sub: user.id,
      email: user.email,
      encryptionKey: encryptionKeyBase64,
    };

    const accessToken = await this.jwtService.signAsync(
      { ...payload },
      {
        secret: process.env.JWT_SECRET,
        expiresIn: process.env.JWT_EXPIRES_IN || '15m',
      },
    );

    // Генерувати refresh token
    const refreshToken = await this.refreshTokenService.generateRefreshToken(user.id);

    return {
      user: this.authMapper.toUserDomain(user),
      accessToken,
      refreshToken,
    };
  }

  async refresh(refreshToken: string): Promise<IRefreshResult> {
    // Верифікувати refresh token
    const { userId, tokenId } = await this.refreshTokenService.verifyRefreshToken(refreshToken);

    // Знайти користувача
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Відкликати старий refresh token (rotation)
    await this.refreshTokenService.revokeRefreshToken(tokenId);

    // ⭐ Отримати encryptionKey з Redis
    const encryptionKey = await this.encryptionKeyCache.get(userId);
    const hasEncryptionKey = encryptionKey !== null;

    // Генерувати новий access token
    const payload: IJwtPayload = {
      sub: user.id,
      email: user.email,
      encryptionKey: encryptionKey || '', // Порожній якщо немає в кеші
    };

    const accessToken = await this.jwtService.signAsync(
      { ...payload },
      {
        secret: process.env.JWT_SECRET,
        expiresIn: process.env.JWT_EXPIRES_IN || '15m',
      },
    );

    // ⭐ Продовжити TTL в Redis якщо ключ існує
    if (hasEncryptionKey) {
      await this.encryptionKeyCache.refresh(userId);
    }

    // Генерувати новий refresh token (rotation)
    const newRefreshToken = await this.refreshTokenService.generateRefreshToken(userId);

    return {
      accessToken,
      refreshToken: newRefreshToken,
      hasEncryptionKey,
    };
  }

  async logout(refreshToken: string, userId?: string): Promise<void> {
    try {
      const { tokenId, userId: tokenUserId } = await this.refreshTokenService.verifyRefreshToken(refreshToken);
      await this.refreshTokenService.revokeRefreshToken(tokenId);

      // ⭐ НЕ видаляємо encryptionKey з Redis при logout
      // Це дозволяє користувачу залогінитись з іншого пристрою
      // Видаляємо тільки при logout-all
    } catch {
      // Ігноруємо помилки
    }
  }

  async logoutAll(userId: string): Promise<void> {
    await this.refreshTokenService.revokeAllUserTokens(userId);

    // ⭐ Видалити encryptionKey з Redis
    await this.encryptionKeyCache.delete(userId);
  }

  async register(email: string, password: string): Promise<IUser> {
    const existingUser = await this.prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      throw new ConflictException('User already exists');
    }

    const encryptionSalt = this.encryptionService.generateSalt();
    const passwordHash = bcrypt.hashSync(password, 10);

    const user = await this.prisma.user.create({
      data: { email, passwordHash, encryptionSalt },
    });

    return this.authMapper.toUserDomain(user);
  }
}
```

### Крок 6: Оновити Auth Controller

**Файл:** `src/slices/users/auth/auth.controller.ts`

```typescript
@Public()
@Post('refresh')
@HttpCode(HttpStatus.OK)
@ApiOperation({ summary: 'Refresh access token' })
async refresh(
  @Req() req: Request,
  @Body() dto: RefreshDto,
  @Res({ passthrough: true }) res: Response,
) {
  const refreshToken = req.cookies?.refreshToken || dto.refreshToken;

  if (!refreshToken) {
    throw new UnauthorizedException('Refresh token not provided');
  }

  const result = await this.authGateway.refresh(refreshToken);

  this.setRefreshTokenCookie(res, result.refreshToken);

  return {
    accessToken: result.accessToken,
    tokenType: 'Bearer',
    expiresIn: 900,
    hasEncryptionKey: result.hasEncryptionKey, // ⭐ Клієнт знає чи може шифрувати
  };
}
```

### Крок 7: Оновити Auth Module

**Файл:** `src/slices/users/auth/auth.module.ts`

```typescript
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { APP_GUARD } from '@nestjs/core';
import { AuthController } from './auth.controller';
import { AuthGateway } from './data/auth.gateway';
import { AuthMapper } from './data/auth.mapper';
import { RefreshTokenService } from './data/refresh-token.service';
import { EncryptionKeyCacheService } from './data/encryption-key-cache.service';
import { AuthGuard } from './auth.guard';
import { PrismaModule } from '#prisma/prisma.module';
import { RedisModule } from '#core/redis/redis.module';
import { EncryptionService } from '#core/domain/services/encryption.service';

@Module({
  imports: [
    PrismaModule,
    RedisModule, // ⭐ Додано
    JwtModule.register({
      global: true,
      secret: process.env.JWT_SECRET,
      signOptions: { expiresIn: process.env.JWT_EXPIRES_IN || '15m' },
    }),
  ],
  controllers: [AuthController],
  providers: [
    AuthGateway,
    AuthMapper,
    RefreshTokenService,
    EncryptionKeyCacheService, // ⭐ Додано
    EncryptionService,
    {
      provide: APP_GUARD,
      useClass: AuthGuard,
    },
  ],
  exports: [AuthGateway],
})
export class AuthModule {}
```

### Крок 8: Docker Compose для Redis

**Файл:** `docker-compose.yml`

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:16
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: root
      POSTGRES_DB: accesslog
    ports:
      - '5432:5432'
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    ports:
      - '6379:6379'
    volumes:
      - redis_data:/data
    command: redis-server --appendonly yes

volumes:
  postgres_data:
  redis_data:
```

---

### Використання на клієнті з Redis

```typescript
// Login
const loginResponse = await fetch('/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',
  body: JSON.stringify({ email, password }),
});

const { accessToken } = await loginResponse.json();
// accessToken завжди має encryptionKey після login

// Refresh
const refreshResponse = await fetch('/auth/refresh', {
  method: 'POST',
  credentials: 'include',
});

const { accessToken: newToken, hasEncryptionKey } = await refreshResponse.json();

if (!hasEncryptionKey) {
  // Redis TTL закінчився (7+ днів без активності)
  // Показати діалог для повторного логіну
  showReloginDialog('Your session has expired for encryption operations');
}
```

---

### Безпека Redis

| Аспект | Рекомендація |
|--------|--------------|
| Доступ | Redis тільки в приватній мережі |
| Пароль | Встановити AUTH пароль в production |
| TLS | Використовувати TLS для зовнішніх з'єднань |
| TTL | Не більше 7-30 днів |
| Ключі | Префікс `encryption:` для ізоляції |
| Backup | Redis дані не критичні (можна відновити через re-login) |

---

### Коли Redis TTL закінчується

```
День 1: Login → encryptionKey в Redis (TTL = 7 днів)
День 2: Refresh → TTL продовжено до 7 днів
День 3: Refresh → TTL продовжено до 7 днів
...
День 8: Refresh → TTL продовжено до 7 днів

Якщо користувач не активний 7+ днів:
→ Redis key expired
→ Refresh повертає hasEncryptionKey: false
→ Клієнт показує діалог для re-login
```

Це найкращий баланс між безпекою та UX.
