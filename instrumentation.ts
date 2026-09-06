import * as Sentry from "@sentry/nextjs";

export async function register() {
  if (process.env.NEXT_RUNTIME === "nodejs") {
    await import("./sentry.server.config");

    // Validates required production env vars (admin password strength, Stripe,
    // DB, Redis, webhook signing pepper, HTTPS app URL) on server startup.
    // Observability-only until BEHALFID_ENFORCE_ENV_VALIDATION=true — see lib/env.ts.
    const { assertProductionEnv } = await import("./lib/env");
    assertProductionEnv();
  }

  if (process.env.NEXT_RUNTIME === "edge") {
    await import("./sentry.edge.config");
  }
}

export const onRequestError = Sentry.captureRequestError;
