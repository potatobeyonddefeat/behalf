import crypto from "crypto";
import { Secret, TOTP } from "otpauth";
import { timingSafeEqualString } from "@/lib/crypto";
import { hashApiKey } from "@/lib/auth";

const MFA_CHALLENGE_TTL_MS = 5 * 60 * 1000;
const BACKUP_CODE_COUNT = 8;

function mfaEncryptionKey(): Buffer {
  const material =
    process.env.BEHALFID_MFA_PEPPER?.trim() ||
    process.env.BEHALFID_SETUP_TOKEN?.trim() ||
    process.env.BEHALFID_ADMIN_PASSWORD?.trim();

  if (!material) {
    if (process.env.NODE_ENV === "production") {
      throw new Error(
        "Refusing to encrypt/decrypt an MFA secret in production: BEHALFID_MFA_PEPPER, " +
          "BEHALFID_SETUP_TOKEN, and BEHALFID_ADMIN_PASSWORD are all unset. Falling back to a " +
          "hardcoded key would let anyone with repo access decrypt stored TOTP secrets."
      );
    }
    return crypto.scryptSync("dev-only-mfa-pepper", "behalfid:mfa-enc:v1", 32);
  }

  return crypto.scryptSync(material, "behalfid:mfa-enc:v1", 32);
}

export function encryptMfaSecret(plaintext: string): string {
  const key = mfaEncryptionKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `v1:${iv.toString("base64url")}:${tag.toString("base64url")}:${encrypted.toString("base64url")}`;
}

export function decryptMfaSecret(payload: string): string {
  const [version, ivB64, tagB64, dataB64] = payload.split(":");
  if (version !== "v1" || !ivB64 || !tagB64 || !dataB64) {
    throw new Error("Invalid MFA secret payload.");
  }
  const key = mfaEncryptionKey();
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(ivB64, "base64url")
  );
  decipher.setAuthTag(Buffer.from(tagB64, "base64url"));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(dataB64, "base64url")),
    decipher.final()
  ]);
  return decrypted.toString("utf8");
}

export function generateTotpSecret(): { secretBase32: string; otpauthUrl: string } {
  const secret = new Secret({ size: 20 });
  const totp = new TOTP({
    issuer: "BehalfID",
    label: "BehalfID",
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    secret
  });
  return {
    secretBase32: secret.base32,
    otpauthUrl: totp.toString()
  };
}

export function verifyTotpCode(secretBase32: string, code: string): boolean {
  const normalized = code.replace(/\s+/g, "");
  if (!/^\d{6}$/.test(normalized)) return false;
  const totp = new TOTP({
    issuer: "BehalfID",
    label: "BehalfID",
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    secret: Secret.fromBase32(secretBase32)
  });
  const delta = totp.validate({ token: normalized, window: 1 });
  return delta !== null;
}

export function generateBackupCodes(): { codes: string[]; hashes: string[] } {
  const codes: string[] = [];
  const hashes: string[] = [];
  for (let i = 0; i < BACKUP_CODE_COUNT; i += 1) {
    const code = crypto.randomBytes(5).toString("hex");
    codes.push(code);
    hashes.push(hashApiKey(`mfa-backup:${code}`));
  }
  return { codes, hashes };
}

export function consumeBackupCode(
  hashes: string[],
  code: string
): { ok: boolean; remainingHashes: string[] } {
  const candidate = hashApiKey(`mfa-backup:${code.trim().toLowerCase()}`);
  const idx = hashes.findIndex((h) => timingSafeEqualString(h, candidate));
  if (idx < 0) return { ok: false, remainingHashes: hashes };
  return {
    ok: true,
    remainingHashes: hashes.filter((_, i) => i !== idx)
  };
}

function challengeSigningKey(): Buffer {
  return mfaEncryptionKey();
}

export async function createMfaChallengeToken(userId: string): Promise<string> {
  const issuedAt = Date.now();
  const nonce = crypto.randomBytes(8).toString("base64url");
  const payload = `${userId}.${issuedAt}.${nonce}`;
  // Short-lived MFA challenge binding (not a password hash). Password auth uses scrypt.
  // codeql[js/insufficient-password-hash]: hmac-challenge-token-not-password
  const sig = crypto.scryptSync(payload, challengeSigningKey(), 32).toString("base64url");
  return `${payload}.${sig}`;
}

export function verifyMfaChallengeToken(token: string): { userId: string } | null {
  const parts = token.split(".");
  if (parts.length !== 4) return null;
  const [userId, issuedAtRaw, nonce, sig] = parts;
  if (!userId || !issuedAtRaw || !nonce || !sig) return null;
  const issuedAt = Number(issuedAtRaw);
  if (!Number.isFinite(issuedAt) || Date.now() - issuedAt > MFA_CHALLENGE_TTL_MS) {
    return null;
  }
  const payload = `${userId}.${issuedAtRaw}.${nonce}`;
  const expected = crypto.scryptSync(payload, challengeSigningKey(), 32).toString("base64url");
  if (!timingSafeEqualString(sig, expected)) return null;
  return { userId };
}
