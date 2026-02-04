import { Injectable } from "@nestjs/common";
import * as crypto from "crypto";

@Injectable()
export class EncryptionService {
    constructor() { }

    generateSalt() {
        return crypto.randomBytes(32).toString("hex"); // 256 bit
    }

    deriveKey(password: string, salt: string) {
        return crypto.pbkdf2Sync(
            password,
            Buffer.from(salt, "hex"),
            100000,
            32,
            "sha512"
        );
    }

    encrypt(plaintext: string, key: string) {
        return crypto.createCipheriv("aes-256-cbc", key, crypto.randomBytes(16)).update(plaintext, "utf8", "hex");
    }

    decrypt(ciphertext: string, key: string) {
        return crypto.createDecipheriv("aes-256-cbc", key, crypto.randomBytes(16)).update(ciphertext, "hex", "utf8");
    }
}
