import crypto from "crypto";
import { cookies } from "next/headers";
import type { NextRequest, NextResponse } from "next/server";
import { timingSafeEqualString } from "@/lib/crypto";
import { checkRateLimit, rateLimitError } from "@/lib/rateLimit";
import { jsonError } from "@/lib/responses";
import { findActiveConsoleAdmin } from "@/lib/consoleAdmins";

export const CONSOLE_COOKIE_NAME = "behalfid_console";
const SESSION_TTL_SECONDS = 60 * 60 * 8;
const MUTATION_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);
// Keep in sync with UNSAFE_ADMIN_PASSWORDS in lib/env.ts (validateProductionEnv) —
// this is the runtime gate; that one is the boot-time check.
const UNSAFE_ADMIN_PASSWORDS = new Set(["change-me", "changeme", "password", "admin", "replace-this-password"]);

function getAdminPassword() {
  const password = process.env.BEHALFID_ADMIN_PASSWORD?.trim() ?? "";
  if (process.env.NODE_ENV === "production" && UNSAFE_ADMIN_PASSWORDS.has(password.toLowerCase())) {
    return "";
  }

  return password;
}

export function isPublicAgentCreationEnabled() {
  return process.env.BEHALFID_PUBLIC_AGENT_CREATION === "true";
}

export function isSetupTokenConfigured() {
  return Boolean(process.env.BEHALFID_SETUP_TOKEN?.trim());
}

function signSession(issuedAt: number, nonce: string, password: string) {
  return crypto.createHmac("sha256", password).update(`${issuedAt}.${nonce}`).digest("base64url");
}

function normalizeOrigin(value?: string | null) {
  if (!value) {
    return null;
  }

  try {
    return new URL(value).origin;
  } catch {
    return null;
  }
}

function getAllowedConsoleOrigins(request: NextRequest) {
  const origins = new Set<string>([request.nextUrl.origin]);
  const configuredOrigin = normalizeOrigin(process.env.NEXT_PUBLIC_APP_URL);
  const vercelOrigin = process.env.VERCEL_URL
    ? normalizeOrigin(`https://${process.env.VERCEL_URL}`)
    : null;

  if (configuredOrigin) {
    origins.add(configuredOrigin);
  }

  if (vercelOrigin) {
    origins.add(vercelOrigin);
  }

  return origins;
}

export function requireConsoleMutationOrigin(request: NextRequest) {
  if (!MUTATION_METHODS.has(request.method)) {
    return null;
  }

  const origin = normalizeOrigin(request.headers.get("origin"));
  if (!origin || !getAllowedConsoleOrigins(request).has(origin)) {
    return jsonError("Invalid request origin.", 403);
  }

  return null;
}

export function verifyAdminPassword(candidate: string) {
  const password = getAdminPassword();
  if (!password || !candidate) {
    return false;
  }

  return timingSafeEqualString(
    crypto.createHash("sha256").update(candidate).digest("hex"),
    crypto.createHash("sha256").update(password).digest("hex")
  );
}

export function verifySetupToken(candidate: string) {
  const token = process.env.BEHALFID_SETUP_TOKEN?.trim() ?? "";
  if (!token || !candidate) {
    return false;
  }

  return timingSafeEqualString(
    crypto.createHash("sha256").update(candidate).digest("hex"),
    crypto.createHash("sha256").update(token).digest("hex")
  );
}

export function getSetupToken(request: NextRequest) {
  const header = request.headers.get("authorization") ?? "";
  const [scheme, token, extra] = header.trim().split(/\s+/);
  if (scheme?.toLowerCase() !== "bearer" || !token || extra) {
    return null;
  }

  return token;
}

export function hasValidSetupToken(request: NextRequest) {
  return verifySetupToken(getSetupToken(request) ?? "");
}

function getSessionSigningSecret() {
  return (
    process.env.BEHALFID_SETUP_TOKEN?.trim() ||
    process.env.BEHALFID_ADMIN_PASSWORD?.trim() ||
    "dev-console-session"
  );
}

function signAdminSession(adminId: string, issuedAt: number, nonce: string) {
  return crypto
    .createHmac("sha256", getSessionSigningSecret())
    .update(`admin.${adminId}.${issuedAt}.${nonce}`)
    .digest("base64url");
}

export function createConsoleAdminSessionValue(adminId: string) {
  const issuedAt = Date.now();
  const nonce = crypto.randomBytes(12).toString("base64url");
  return `v2.${adminId}.${issuedAt}.${nonce}.${signAdminSession(adminId, issuedAt, nonce)}`;
}

export function parseConsoleSession(value?: string): { kind: "shared" } | { kind: "admin"; adminId: string } | null {
  if (!value) return null;
  if (value.startsWith("v2.")) {
    const parts = value.split(".");
    if (parts.length !== 5) return null;
    const [, adminId, issuedAtRaw, nonce, signature] = parts;
    const issuedAt = Number(issuedAtRaw);
    if (!adminId || !Number.isFinite(issuedAt) || !nonce || !signature) return null;
    if (issuedAt + SESSION_TTL_SECONDS * 1000 <= Date.now()) return null;
    if (!timingSafeEqualString(signature, signAdminSession(adminId, issuedAt, nonce))) return null;
    return { kind: "admin", adminId };
  }
  if (isValidSharedConsoleSession(value)) {
    return { kind: "shared" };
  }
  return null;
}

function isValidSharedConsoleSession(value?: string) {
  const password = getAdminPassword();
  if (!password || !value) {
    return false;
  }

  const parts = value.split(".");
  if (parts.length !== 3) {
    return false;
  }

  const [issuedAtRaw, nonce, signature] = parts;
  const issuedAt = Number(issuedAtRaw);
  if (!Number.isFinite(issuedAt) || !nonce || !signature) {
    return false;
  }

  if (issuedAt + SESSION_TTL_SECONDS * 1000 <= Date.now()) {
    return false;
  }

  return timingSafeEqualString(signature, signSession(issuedAt, nonce, password));
}

export function createConsoleSessionValue() {
  const password = getAdminPassword();
  if (!password) {
    return null;
  }

  const issuedAt = Date.now();
  const nonce = crypto.randomBytes(12).toString("base64url");
  return `${issuedAt}.${nonce}.${signSession(issuedAt, nonce, password)}`;
}

export function isValidConsoleSession(value?: string) {
  return parseConsoleSession(value) !== null;
}

export async function hasConsoleSession() {
  const cookieStore = await cookies();
  return isValidConsoleSession(cookieStore.get(CONSOLE_COOKIE_NAME)?.value);
}

/** Returns an attributable console principal; shared/legacy sessions are excluded. */
export async function getConsoleAdminPrincipal() {
  const cookieStore = await cookies();
  const session = parseConsoleSession(cookieStore.get(CONSOLE_COOKIE_NAME)?.value);
  if (session?.kind !== "admin") return null;
  return findActiveConsoleAdmin(session.adminId);
}

export async function requireConsoleApi(request: NextRequest) {
  const limit = await checkRateLimit(request);
  if (limit.limited) {
    return rateLimitError();
  }

  const originError = requireConsoleMutationOrigin(request);
  if (originError) {
    return originError;
  }

  if (!isValidConsoleSession(request.cookies.get(CONSOLE_COOKIE_NAME)?.value)) {
    return jsonError("Console authentication required.", 401);
  }

  return null;
}

export function requireSetupTokenOrConsoleSession(request: NextRequest) {
  if (hasValidSetupToken(request)) {
    return null;
  }

  if (!isValidConsoleSession(request.cookies.get(CONSOLE_COOKIE_NAME)?.value)) {
    return jsonError("Agent creation is disabled for public requests.", 403);
  }

  const originError = requireConsoleMutationOrigin(request);
  if (originError) {
    return originError;
  }

  return null;
}

export function requireSetupTokenOrConsoleApi(request: NextRequest) {
  if (hasValidSetupToken(request)) {
    return null;
  }

  if (!isValidConsoleSession(request.cookies.get(CONSOLE_COOKIE_NAME)?.value)) {
    return jsonError("Console authentication or setup token required.", 401);
  }

  const originError = requireConsoleMutationOrigin(request);
  if (originError) {
    return originError;
  }

  return null;
}

export function setConsoleSessionCookie(response: NextResponse, value: string) {
  // Always host-only: console must not share session cookies with auth/app.
  response.cookies.set(CONSOLE_COOKIE_NAME, value, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: SESSION_TTL_SECONDS,
    path: "/"
  });
}

export function clearConsoleSessionCookie(response: NextResponse) {
  response.cookies.set(CONSOLE_COOKIE_NAME, "", {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 0,
    path: "/"
  });
}
