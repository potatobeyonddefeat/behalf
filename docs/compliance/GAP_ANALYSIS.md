# BehalfID — SOC 2 / ISO 27001 Gap Analysis

**Assessment date:** 2026-07-24  
**Basis:** [CONTROL_MATRIX.md](./CONTROL_MATRIX.md) + code/docs review  
**Scope:** Security, Processing Integrity, Availability (SOC 2) + ISO 27001:2022 Annex A / ISMS readiness  
**Method:** Design effectiveness review against repository evidence (not Type II operating-period sampling)

> Interactive view: open the gap analysis canvas beside chat (see evidence pack README).

---

## 1. Executive summary

BehalfID has a **solid technical control foundation** for a permission-verification SaaS (hashed secrets, RBAC, validation, HMAC webhooks, SSRF guards, CI, structured audit logs). Readiness for SOC 2 Type II and ISO 27001 is blocked primarily by:

1. **Organizational / ISMS gaps** (policies, risk register, IR/BCP, vendor assessments, access reviews, management review).
2. **Availability / continuity gaps** (no documented/tested backups, RTO/RPO, APM/alerting).
3. **Access & monitoring gaps** (no MFA, shared console admin password, no failed-auth logging).
4. **Public claim drift** on `/compliance` vs actual session and retention behavior.

| Score dimension | Implemented | Partial | Missing | N/A |
|-----------------|-------------|---------|---------|-----|
| Security (CC) | 5 | 10 | 3 | 0 |
| Processing Integrity (PI) | 3 | 2 | 1 | 0 |
| Availability (A) | 0 | 4 | 2 | 0 |
| ISO org / ISMS | 0 | 1 | 6 | 0 |

*Counts are control-row aggregates from §3; see matrix for detail.*

---

## 2. Critical and high gaps (priority order)

| Gap ID | Severity | Area | Finding | Criteria | Recommended remediation |
|--------|----------|------|---------|----------|-------------------------|
| G-01 | Critical | Integrity / Trust | REMEDIATED 2026-07-24: compliance copy matches SameSite=Lax + 1h/14d | PI1.5, CC6.7, A.8.5 | Keep copy in sync with session code |
| G-02 | Critical | Integrity / Trust | REMEDIATED 2026-07-24: plan-based retention disclosed; purge cron added (originally Mongo; runs against Postgres since the 2026-07-31 datastore cutover — `lib/logPurge.ts`) | PI1.5, CC7.1, A.8.10 | Schedule `/api/cron/purge-logs` in prod |
| G-03 | High | Security | REMEDIATED 2026-07-24: developer TOTP MFA | CC6.1, A.8.5 | Encourage OWNER enroll; optional console MFA later |
| G-04 | High | Security | REMEDIATED 2026-07-24: ConsoleAdmin + audit log; shared password bootstrap/legacy | CC6.8, A.8.2 | Set `BEHALFID_ALLOW_SHARED_ADMIN=false` after bootstrap |
| G-05 | High | Security | REMEDIATED 2026-07-24: AuthEvent failed-auth logging | CC7.1, A.8.15 | Monitor AuthEvent spikes |
| G-06 | High | Availability | PARTIAL: backup/restore runbook published; restore drill still required | A1.2, A.5.30, A.8.13 | Complete quarterly restore drill |
| G-07 | High | Availability | PARTIAL: Sentry + MONITORING.md; external uptime still recommended | CC7.2, A1.1, A.8.16 | Configure SENTRY_DSN + uptime checks |
| G-08 | High | ISMS | No formal ISMS leadership approval yet | Clauses 4–10, A.5.1 | Approve policies / SoA / risk register |
| G-09 | High | ISMS | REMEDIATED 2026-07-24: IR + BCP runbooks | CC7.3, A.5.24–28 | Staff on-call roster outside repo |
| G-10 | Medium | Security | API key hashes deterministic SHA-256 without pepper | CC6.6, A.8.24 | HMAC pepper or key-id + HMAC design per `docs/SECURITY.md` |
| G-11 | Medium | Security | PARTIAL 2026-08-12: added `.github/dependabot.yml` (npm across root/packages/examples + github-actions) for automated dependency PRs; CodeQL already runs via GitHub's default setup (not a committed workflow, per prior "Fix CodeQL alerts" history) — no remediation-SLA tracking process yet | CC7.4, A.8.8 | Track remediation SLA once Dependabot PRs start landing |
| G-12 | Medium | Change | App production deploy not gated by in-repo change-control workflow | CC8.1, A.8.32 | Deploy approvals, env separation, deploy audit trail |
| G-13 | Medium | Integrity | PARTIAL 2026-08-12: Postgres cutover added real `db.transaction()` for account/agent/webhook writes and cascade deletes; webhook outbox delivery itself is still at-least-once, not transactional | PI1.3 | Use transactions or dual-write compensation for webhook delivery specifically |
| G-14 | Medium | Availability | Webhook worker is cron API route, not dedicated queue | A1.2, A.8.14 | Queue service or hardened worker with observability |
| G-15 | Medium | Security | Rate-limit memory fallback weak if Redis unreachable at runtime | CC9.1 | Fail closed / degrade safely; alert on Redis loss |
| G-16 | Medium | ISMS | No documented vendor risk assessments for subprocessors | A.5.19–22 | Annual vendor reviews; track BAAs/DPAs |
| G-17 | Low | Security | No CSRF tokens beyond SameSite + Origin | CC6.1 | Document residual risk or add CSRF tokens for cookie auth |
| G-18 | Low | Security | Product still self-describes as prototype unsuitable for open multi-tenant without hardening | CC / marketing | Either harden multi-tenant posture or keep scope constrained in auditor system description |
| G-19 | Low | Integrity | Verify `metadata` can hold sensitive fields when enabled | PI1.1, C1 | Default metadata off in prod; customer guidance |
| G-20 | Low | Enforcement | Some agent paths fail open (e.g. Claude Code hook outage); Site Guard UA spoofable | CC9.2 | Document as residual risk; prefer fail-closed integrations |
| G-21 | Critical | Integrity / Trust / GDPR / CPRA | REMEDIATED 2026-08-12: public pages and pack described the primary datastore as MongoDB Atlas after production had already cut over to Supabase (Postgres) on 2026-07-31, incl. `app/privacy/page.tsx` and `app/compliance/page.tsx` subprocessor/data-transfer claims | PI1.5, GDPR Art. 13/14, CPRA §1798.100 | Keep infra references in sync with `docs/PRODUCTION.md` on future migrations |
| G-22 | Critical | GDPR / CPRA | REMEDIATED 2026-08-12: `app/privacy/page.tsx` (static `/privacy` route) stated "no third-party analytics... no tracking cookies" while HeyCatch (consent-gated) is live and receives name/email once accepted; the `/[locale]/privacy` route's `messages/*.json` copy already disclosed this correctly, so only the static English route had drifted | GDPR Art. 13/14 | Keep both routes' disclosures in sync going forward |
| G-23 | High | GDPR | REMEDIATED 2026-08-12: Mongo-backend `deleteDeveloperUserCredentials` (`lib/repositories/mongo/accountDeletion.ts`) removed sessions/tokens/user but left `ExternalIdentity` (OAuth-linked email) and `PasskeyCredential` rows keyed to the deleted user. Postgres backend was already safe via `ON DELETE CASCADE` | GDPR Art. 17 | N/A — fixed to mirror Postgres cascade behavior |
| G-24 | Medium | Security | REMEDIATED 2026-08-12: `developer_token` was a declared `AUTH_EVENT_SURFACES` value but `authenticateDeveloperToken` never called `recordAuthFailure`, so invalid `x-developer-token` attempts went unlogged while every other auth surface (login, console, API key, MFA) was covered | CC7.1, A.8.15 | N/A — fixed |
| G-25 | Medium | GDPR / CPRA | REMEDIATED 2026-08-12: added `GET /api/auth/account/export` + a "Export your data" dashboard section (`components/dashboard/DataExportSection.tsx`), so access/portability are now genuinely self-service via the developer portal, matching the existing public claim | GDPR Art. 15/20 | Keep the export payload in sync as new profile fields are added |
| G-26 | Medium | GDPR | REMEDIATED 2026-08-12: `IdentityAuditLog` rows are now deleted as part of `deleteDeveloperUserCredentials` on account deletion, on both backends. Note: `lib/authProviders/identityAudit.ts` writes unconditionally to Postgres (`identity_audit_logs`) regardless of `BEHALFID_REPOSITORY_BACKEND` — the Mongo `IdentityAuditLog` model was already unreferenced outside this deletion path, so the Postgres-side fix is the one that matters in practice; the Mongo-side deletion call is defensive/dead-path parity | GDPR Art. 5(1)(e), Art. 17 | N/A — fixed. Indefinite retention while the account is active is unchanged and matches the design intent (durable account-security history, like `AdminAuditLog`/`CliAuditLog`) |
| G-27 | Medium | ISMS / GDPR | HeyCatch (analytics) and Supabase (datastore) are both new/changed subprocessors since the last vendor review; neither has a documented DPA/SCC assessment in-repo (extends existing G-16) | A.5.19–22, GDPR Art. 28 | Complete vendor risk assessment + DPA confirmation for both |
| G-28 | Critical | Security / Config | PARTIAL 2026-08-14: `assertProductionEnv()` (`lib/env.ts`) existed as a fail-closed boot guard but was called nowhere outside its own unit test — not from `instrumentation.ts`, middleware, or any startup script — so a production deploy with a placeholder admin password, missing Stripe/DB/Redis config, or a non-HTTPS app URL would boot without complaint. Wired into `instrumentation.ts`'s `register()`. Ships **log-only** (console.error, doesn't block boot) until `BEHALFID_ENFORCE_ENV_VALIDATION=true` is explicitly set, so this change cannot itself take down a live deployment before its required-var list has been verified against the real production environment | ISO A.8.9, SOC2 CC6.1/CC8.1 | Operator: confirm `validateProductionEnv()` reports `valid: true` for prod, then set `BEHALFID_ENFORCE_ENV_VALIDATION=true` to promote to fail-closed |
| G-29 | High | Security / Cryptography | REMEDIATED 2026-08-14: `deriveSigningKey` (`lib/webhooks.ts`) silently used the raw `secret_hash` column value as the webhook HMAC key whenever `BEHALFID_WEBHOOK_SIGNING_PEPPER` was unset — DB read access alone (backup leak, over-privileged replica) was sufficient to forge signed `verification.*`/`approval.*` webhook events, and nothing enforced setting the pepper. Moved to the required-production-env list (enforced once G-28 is flipped on) and added a one-time production warning on first use if still missing | ISO A.8.24, SOC2 CC6.6/PI1.3 | Operator: set `BEHALFID_WEBHOOK_SIGNING_PEPPER` in production (`openssl rand -hex 32`) |
| G-30 | Medium | Security / Cryptography | REMEDIATED 2026-08-14: `mfaEncryptionKey` (`lib/mfa.ts`) fell back to the hardcoded literal `"dev-only-mfa-pepper"` — public in source — as the AES-256-GCM key protecting stored TOTP secrets, if `BEHALFID_MFA_PEPPER`/`SETUP_TOKEN`/`ADMIN_PASSWORD` were all unset, with no production guard. Now throws instead of using that fallback in production | ISO A.8.24, SOC2 CC6.1 | N/A — fixed |
| G-31 | Medium | Confidentiality | REMEDIATED 2026-08-14: `getPostgresDb()` (`lib/db/postgres/index.ts`) passed no `ssl` option to the Postgres client, so TLS enforcement depended entirely on whether the pasted `DATABASE_URL` happened to encode `sslmode=require`. Now forces `ssl: "require"` whenever the app runs in production (Vercel prod / `NODE_ENV=production`); local/CI Postgres per AGENTS.md is unaffected | ISO A.8.24, SOC2 CC6.7, GDPR Art. 32 | N/A — fixed |
| G-32 | Low | Integrity / GDPR / CPRA | PARTIAL 2026-08-14 (extends G-19): `lib/verificationLogs.ts` carried its own drifted copy of the four secret-token regexes in `lib/secretRedaction.ts` instead of importing it, and neither matched general PII (e.g. an email address embedded in caller-supplied verification `metadata`) — only known token formats. Consolidated `verificationLogs.ts` onto the shared `redactSecrets()` and added an email-address pattern there, which also improves Sentry `beforeSend` scrubbing (same function). G-19's core point — arbitrary metadata can still carry non-email PII — remains open | GDPR Art. 5(1)(c), CPRA §1798.100, SOC2 PI1.1/C1 | Still open: default `BEHALFID_LOG_METADATA=false` in prod guidance, or add a broader PII scrubber (per G-19) |

**HIPAA:** reviewed 2026-08-12 — BehalfID does not process Protected Health Information and the public `/compliance` page correctly states this with a BAA-on-request path if that changes. No gap logged; treated as out of scope, not silently skipped.

---

## 3. Control-by-control status

### Security

| Control | Status | Severity if gap | Notes |
|---------|--------|-----------------|-------|
| Authn (passwords, OIDC, API keys) | Partial | High | Strong hashing/compare; no MFA |
| RBAC / membership | Implemented | — | OWNER→VIEWER authority model |
| Tenant isolation | Partial | Medium | Logical `accountId` only |
| Secret storage (hashes) | Partial | Medium | Good hashing; no pepper; host encryption for DB |
| Session management | Partial | Critical* | Works; **public claims wrong** |
| Privileged console | Partial | High | Shared password |
| Security logging (verify) | Partial | High | Strong decision logs; missing failed-auth |
| Monitoring / APM | Missing | High | Health only |
| Vuln management | Partial | Medium | Manual npm audit history |
| CI change control | Implemented | — | Strong CI |
| Release provenance (CLI) | Implemented | — | Provenance + checksums |
| Deploy change control (app) | Partial | Medium | Manual Vercel |
| Rate limiting | Partial | Medium | Redis required in env; fallback risk |
| SSRF / egress | Implemented | — | Strong product controls |
| Fail-closed design | Partial | Low–Med | Integration-dependent |
| CSP / browser headers | Implemented | — | Nonce CSP + reports |

\*Severity elevated because inaccurate public disclosures create auditor / customer trust failure (PI1.5), not because sessions are insecure by design.

### Processing integrity

| Control | Status | Severity if gap | Notes |
|---------|--------|-----------------|-------|
| Input validation | Implemented | — | Field whitelists |
| Webhook / Stripe / Slack integrity | Implemented | — | HMAC / signatures / idempotency |
| End-to-end processing consistency | Partial | Medium | No transactions; at-least-once webhooks |
| Origin checks | Partial | Low | SameSite+Origin, no CSRF token |
| Public disclosure accuracy | Implemented | — | REMEDIATED 2026-08-12 (G-21/G-22): `/privacy` and `/compliance` now correctly disclose Supabase (Postgres) as the datastore and HeyCatch as the consent-gated analytics processor |

### Availability

| Control | Status | Severity if gap | Notes |
|---------|--------|-----------------|-------|
| Health checks | Partial | Medium | Present; no external monitor |
| Backups | Missing | High | Provider capability ≠ evidenced control |
| DR/BCP | Missing | High | Listed in progress on site |
| Provider HA | Partial | Medium | Relies on Vercel/Atlas |
| Async job resilience | Partial | Medium | Outbox/retry/DLQ exists |
| Status page | Partial | Medium | Comms aid, not IR |

### ISO organizational

| Control | Status | Severity if gap | Notes |
|---------|--------|-----------------|-------|
| Policies / ISMS | Missing | High | Required for certification |
| Asset register | Partial | Medium | Privacy categories only |
| Supplier security | Missing | High | No assessment pack |
| Incident management | Missing | High | Status ≠ IR |
| Access review cadence | Missing | Medium | Product RBAC ≠ infra reviews |
| Performance evaluation (internal audit / mgmt review) | Missing | High | This engagement is first structured internal audit |

---

## 4. Strengths to preserve

- One-way hashed API keys, sessions, webhook secrets, site keys; timing-safe compares.
- scrypt passwords; Google OIDC with PKCE; workspace Google SSO domain enforcement.
- Workspace RBAC and account-scoped dashboard APIs.
- Verification audit trail with stable `requestId` and secret redaction.
- HMAC-signed webhooks, SSRF URL validation, Stripe/Slack signature verification.
- Field-whitelist validation; CSP with reporting endpoint.
- CI with tests + CLI release provenance.
- Egress proxy / MCP audit tooling for enforcement-at-boundary use cases.

---

## 5. Readiness verdict

| Framework | Ready for external audit kickoff? | Blocking themes |
|-----------|-----------------------------------|-----------------|
| SOC 2 Type I (design) | **Near** — after fixing claim drift + documenting system description & control owners | G-01, G-02, G-04, G-05, G-08 (minimum policies) |
| SOC 2 Type II (operating effectiveness) | **Not ready** — need observation period evidence: access reviews, IR drills, backup restores, monitoring, change tickets | G-06, G-07, G-09, G-12 + operating evidence |
| ISO 27001 certification | **Not ready** — ISMS must operate (SoA, risk treatment, internal audits, management review) before Stage 1/2 | G-08, G-09, G-16 + clauses 4–10 |

---

## 6. Related artifacts

- [CONTROL_MATRIX.md](./CONTROL_MATRIX.md)
- [SOC2_AUDIT.md](./SOC2_AUDIT.md)
- [ISO27001_AUDIT.md](./ISO27001_AUDIT.md)
- [SOA_DRAFT.md](./SOA_DRAFT.md)
- [README.md](./README.md)
