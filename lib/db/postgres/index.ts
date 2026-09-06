/**
 * Postgres connection module for Drizzle — the authoritative production datastore
 * (Supabase/Postgres) for cutover deployments (`BEHALFID_ALLOW_POSTGRES_RUNTIME=true` +
 * `BEHALFID_REPOSITORY_BACKEND=postgres`). Mongo remains available only as a legacy/test
 * path when the Postgres latch is off — see docs/PRODUCTION.md and docs/CAPABILITY_MATRIX.md.
 */

import { drizzle, type PostgresJsDatabase } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import * as schema from "@/lib/db/postgres/schema";

export type BehalfPostgresDb = PostgresJsDatabase<typeof schema>;

type GlobalPostgresCache = {
  client?: ReturnType<typeof postgres>;
  db?: BehalfPostgresDb;
};

const globalForPostgres = globalThis as typeof globalThis & {
  __behalfPostgres?: GlobalPostgresCache;
};

function resolveDatabaseUrl(): string | undefined {
  return process.env.DATABASE_URL ?? process.env.POSTGRES_URL;
}

// Local/CI Postgres (see AGENTS.md) has no TLS, so this only applies in real
// production — Supabase (the documented production datastore) supports TLS,
// so this makes an already-expected property explicit instead of implicit.
function requiresTls(): boolean {
  return process.env.VERCEL_ENV
    ? process.env.VERCEL_ENV === "production"
    : process.env.NODE_ENV === "production";
}

/**
 * Returns a cached Drizzle client when DATABASE_URL or POSTGRES_URL is set.
 * Throws only when called without a URL — callers should guard with isPostgresConfigured().
 */
export function getPostgresDb(): BehalfPostgresDb {
  const url = resolveDatabaseUrl();
  if (!url) {
    throw new Error(
      "Postgres is not configured. Set DATABASE_URL or POSTGRES_URL to use getPostgresDb()."
    );
  }

  if (!globalForPostgres.__behalfPostgres) {
    globalForPostgres.__behalfPostgres = {};
  }

  const cache = globalForPostgres.__behalfPostgres;

  if (!cache.client) {
    cache.client = postgres(url, {
      max: 1,
      prepare: false,
      idle_timeout: 20,
      connect_timeout: 10,
      ssl: requiresTls() ? "require" : undefined
    });
  }

  if (!cache.db) {
    cache.db = drizzle(cache.client, { schema });
  }

  return cache.db;
}

/** True when a Postgres URL is present in the environment. */
export function isPostgresConfigured(): boolean {
  return Boolean(resolveDatabaseUrl());
}

export { schema };
export * from "@/lib/db/postgres/schema";
export * from "@/lib/db/postgres/enums";
