import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { IJwtPayload } from '#users/auth/domain';

export const User = createParamDecorator(
    (data: keyof IJwtPayload | undefined, ctx: ExecutionContext) => {
        const request = ctx.switchToHttp().getRequest();
        const user = request.user as IJwtPayload;

        if (data) {
            return user[data];
        }

        return user;
    },
);