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

    encrypt(plaintext: string, key: string): string {
        const keyBuffer = Buffer.from(key, 'base64');  // base64 → 32 bytes
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', keyBuffer, iv);
        const encrypted = cipher.update(plaintext, 'utf8', 'hex') + cipher.final('hex');
        return iv.toString('hex') + ':' + encrypted;
    }

    decrypt(ciphertext: string, key: string): string {
        const keyBuffer = Buffer.from(key, 'base64');  // base64 → 32 bytes
        const [ivHex, encrypted] = ciphertext.split(':');
        const iv = Buffer.from(ivHex, 'hex');
        const decipher = crypto.createDecipheriv('aes-256-cbc', keyBuffer, iv);
        return decipher.update(encrypted, 'hex', 'utf8') + decipher.final('utf8');
    }
}
