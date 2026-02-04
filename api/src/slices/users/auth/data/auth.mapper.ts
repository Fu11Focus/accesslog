import { Injectable } from "@nestjs/common";
import { IUser } from "../domain";
import { User } from "@prisma/client";

@Injectable()
export class AuthMapper {
    toUserDomain(user: User): IUser {
        return {
            id: user.id,
            email: user.email,
            plan: user.plan,
            createdAt: user.createdAt,
            updatedAt: user.updatedAt,
        };
    }
}