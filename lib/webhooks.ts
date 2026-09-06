import crypto from "crypto";
import net from "net";
import { createPublicId, createWebhookSecret } from "@/lib/ids";
import { logger } from "@/lib/logger";
import { createEvent } from "@/lib/repositories/webhooks";

export const WEBHOOK_EVENT_TYPES = [
  "verification.allowed",
  "verification.denied",
  "verification.approval_required",
  "verification.shadow",
  "approval.requested",
  "approval.approved",
  "approval.denied",
  "approval.used",
  "agent.created",
  "agent.disabled",
  "agent.enabled",
  "agent.key_rotated",
  "permission.created",
  "permission.revoked"
] as const;

export type WebhookEventType = (typeof WEBHOOK_EVENT_TYPES)[number];

export type WebhookEvent = {
  eventId: string;
  type: WebhookEventType;
  createdAt: string;
  accountId: string;
  developerUserId?: string;
  data: Record<string, unknown>;
};

export const WEBHOOK_MAX_ATTEMPTS = 5;
export const WEBHOOK_BACKOFF_MS = [0, 5_000, 30_000, 120_000, 600_000] as const;

export function hashWebhookSecret(secret: string) {
  return crypto.createHash("sha256").update(secret).digest("hex");
}

export function createWebhookSecretPreview(secret: string) {
  return `${secret.slice(0, 10)}...${secret.slice(-6)}`;
}

export function createSigningSecret() {
  const secret = createWebhookSecret();
  return {
    secret,
    secretHash: hashWebhookSecret(secret),
    secretPreview: createWebhookSecretPreview(secret)
  };
}

export function isWebhookEventType(value: string): value is WebhookEventType {
  return WEBHOOK_EVENT_TYPES.includes(value as WebhookEventType);
}

export function validateWebhookEvents(events: unknown) {
  if (!Array.isArray(events) || events.length === 0) {
    return { events: null, error: "events must be a non-empty array." };
  }

  const normalized = [...new Set(events.map((event) => String(event).trim()))];
  const invalid = normalized.find((event) => !isWebhookEventType(event));
  if (invalid) {
    return { events: null, error: `Unsupported webhook event: ${invalid}.` };
  }

  return { events: normalized as WebhookEventType[], error: null };
}

export function validateWebhookUrl(value: unknown) {
  if (typeof value !== "string" || !value.trim()) {
    return { url: null, error: "url is required." };
  }

  let url: URL;
  try {
    url = new URL(value.trim());
  } catch {
    return { url: null, error: "url must be a valid URL." };
  }

  const hostname = url.hostname.toLowerCase();
  const isLocalhost = hostname === "localhost" || hostname === "127.0.0.1";
  const isProduction = process.env.NODE_ENV === "production";

  if (url.username || url.password) {
    return { url: null, error: "Webhook URLs must not include credentials." };
  }

  if (isProduction && url.protocol !== "https:") {
    return { url: null, error: "Webhook URLs must use https:// in production." };
  }

  if (!isProduction && url.protocol !== "https:" && !(url.protocol === "http:" && isLocalhost)) {
    return { url: null, error: "Webhook URLs must use https://, except localhost over http in development." };
  }

  if (isProduction && isPrivateHostname(hostname)) {
    return { url: null, error: "Webhook URL host is not allowed." };
  }

  url.hash = "";
  url.username = "";
  url.password = "";
  return { url: url.toString(), error: null };
}

export function isPrivateIpAddress(address: string) {
  const normalizedAddress = address.toLowerCase().replace(/^\[|\]$/g, "");
  const ipVersion = net.isIP(normalizedAddress);

  if (ipVersion === 4) {
    const parts = normalizedAddress.split(".").map(Number);
    if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
      return true;
    }

    const [a, b, c, d] = parts;
    return (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 192 && b === 0 && c === 0) ||
      (a === 198 && (b === 18 || b === 19)) ||
      a >= 224 ||
      (a === 255 && b === 255 && c === 255 && d === 255)
    );
  }

  if (ipVersion === 6) {
    const addr = normalizedAddress;
    // Loopback / unspecified
    if (addr === "::" || addr === "::1") return true;
    // Unique Local (fc00::/7)
    if (addr.startsWith("fc") || addr.startsWith("fd")) return true;
    // Link-local (fe80::/10)
    if (addr.startsWith("fe8") || addr.startsWith("fe9") || addr.startsWith("fea") || addr.startsWith("feb")) return true;
    // Multicast (ff00::/8)
    if (addr.startsWith("ff")) return true;
    // IPv4-mapped (::ffff:/96) — compressed form
    if (addr.startsWith("::ffff:")) return true;
    // IPv4-mapped — full form: 0:0:0:0:0:ffff:x.x.x.x or 0000:...:ffff:x.x.x.x
    if (/^(?:0+:){5}ffff:/i.test(addr)) return true;
    // NAT64 (64:ff9b::/96) — could translate private IPv4 addresses
    if (addr.startsWith("64:ff9b:")) return true;
    return false;
  }

  return false;
}

export function createWebhookEvent(
  accountId: string | null | undefined,
  type: WebhookEventType,
  data: Record<string, unknown>,
  developerUserId?: string | null
) {
  // `accountId` must be a real account. It previously fell back to the
  // developer's user id, which Mongo accepted silently — but on Postgres
  // `webhook_events.account_id` is NOT NULL *and* a foreign key to
  // `accounts.account_id`, so a `usr_…` id raised SQLSTATE 23503. Callers that
  // cannot name an account must not emit an account-scoped event at all.
  if (!accountId) {
    logger.warn("webhook_event_skipped_no_account", { type, developerUserId: developerUserId ?? null });
    return null;
  }

  return {
    eventId: createPublicId("evt"),
    type,
    createdAt: new Date().toISOString(),
    accountId,
    developerUserId: developerUserId ?? undefined,
    data
  } satisfies WebhookEvent;
}

/**
 * Fire-and-forget notification enqueue.
 *
 * Deliberately never throws. Webhook delivery is a *nonessential downstream
 * side effect*: callers await it after the primary mutation has already
 * committed, so letting it throw turned a successful write into an unhandled
 * 500. For agent creation that was destructive — the agent and its API-key
 * hash were committed, but the one-time plaintext key only ever existed in the
 * response body that was then never sent, making the credential unrecoverable.
 *
 * Failures are logged with a stable scope and the database error code so they
 * stay diagnosable and alertable rather than silent. Use `enqueueWebhookEvent`
 * directly where the caller genuinely needs the failure to propagate (the
 * delivery worker does).
 */
export async function emitWebhookEvent(event: WebhookEvent | null): Promise<boolean> {
  if (!event) {
    return false;
  }

  try {
    await enqueueWebhookEvent(event);
    return true;
  } catch (error) {
    const detail = error as { name?: string; message?: string; code?: unknown; constraint?: unknown };
    logger.error("webhook_event_enqueue_failed", {
      eventId: event.eventId,
      type: event.type,
      accountId: event.accountId,
      error: detail?.message,
      name: detail?.name,
      ...(detail?.code === undefined ? {} : { code: detail.code }),
      ...(detail?.constraint === undefined ? {} : { constraint: detail.constraint })
    });
    return false;
  }
}

export async function enqueueWebhookEvent(event: WebhookEvent) {
  await createEvent({
    eventId: event.eventId,
    accountId: event.accountId,
    developerUserId: event.developerUserId,
    type: event.type,
    payload: event,
    status: "pending",
    attempts: 0,
    nextAttemptAt: new Date(),
    deadLetter: false,
    lastError: null,
    completedAt: null
  });
}

/**
 * Derive the effective HMAC signing key from the stored secretHash.
 * When BEHALFID_WEBHOOK_SIGNING_PEPPER is set, the key is derived as
 * HMAC-SHA256(pepper, secretHash) so that the value stored in the database
 * is not sufficient on its own to forge signatures — the pepper must also
 * be known. Generate the pepper with: openssl rand -hex 32
 */
let warnedMissingSigningPepperInProduction = false;

function deriveSigningKey(secretHash: string): string {
  const pepper = process.env.BEHALFID_WEBHOOK_SIGNING_PEPPER?.trim();
  if (pepper) {
    return crypto.createHmac("sha256", pepper).update(secretHash).digest("hex");
  }

  if (process.env.NODE_ENV === "production" && !warnedMissingSigningPepperInProduction) {
    warnedMissingSigningPepperInProduction = true;
    console.error(
      "[behalfid] BEHALFID_WEBHOOK_SIGNING_PEPPER is not set: webhook HMAC keys equal the " +
        "secret_hash stored in Postgres, so DB read access alone is sufficient to forge signed " +
        "webhook events. Generate one with: openssl rand -hex 32"
    );
  }

  return secretHash;
}

export function signWebhookPayload(secretHash: string, timestamp: string, rawBody: string) {
  const key = deriveSigningKey(secretHash);
  return crypto.createHmac("sha256", key).update(`${timestamp}.${rawBody}`).digest("hex");
}

function isPrivateHostname(hostname: string) {
  const normalizedHostname =
    hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;

  if (
    normalizedHostname === "localhost" ||
    normalizedHostname.endsWith(".localhost") ||
    normalizedHostname.endsWith(".local") ||
    normalizedHostname.endsWith(".internal")
  ) {
    return true;
  }

  if (isPrivateIpAddress(normalizedHostname)) return true;

  return false;
}
