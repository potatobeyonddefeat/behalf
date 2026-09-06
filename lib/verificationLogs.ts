import { findApprovals } from "@/lib/repositories/approvals";
import { listAgents } from "@/lib/repositories/agents";
import {
  aggregateStats,
  findLogs
} from "@/lib/repositories/verificationLogs";
import { parseSmartLogQuery } from "@/lib/smartSearch/parseLogQuery";
import { redactSecrets } from "@/lib/secretRedaction";

export type LogRisk = "low" | "medium" | "high";

export type LogDecision = "allowed" | "denied" | "approval_required";

export type VerificationLogListItem = {
  requestId: string;
  accountId?: string | null;
  developerUserId?: string | null;
  agentId: string;
  agentName?: string | null;
  permissionId?: string | null;
  action: string;
  amount?: number;
  vendor?: string | null;
  environment?: string | null;
  allowed: boolean;
  approvalRequired?: boolean;
  decision?: LogDecision;
  reason: string;
  risk: LogRisk;
  shadow?: boolean;
  approvalId?: string | null;
  metadata?: Record<string, unknown> | null;
  createdAt?: Date | string;
};

export type VerificationLogSummary = {
  total: number;
  allowed: number;
  denied: number;
  highRisk: number;
  approvalRequired: number;
  topDeniedAction: string | null;
  topVendor: string | null;
};

export type LogPagination = {
  limit: number;
  page: number;
  total: number;
  hasMore: boolean;
};

const RISKS = new Set(["low", "medium", "high"]);
const DEFAULT_LIMIT = 100;
const MAX_LIMIT = 500;
const APPROVAL_REASON_RE = /requires approval|approval required|approval before execution/i;
const SEARCHABLE_FIELDS = ["requestId", "action", "vendor", "reason", "agentId", "permissionId"] as const;

// Delegates to the shared redactor (lib/secretRedaction.ts) so log output and
// Sentry scrubbing can't drift out of sync — this used to be a separate copy
// of the same four regexes with no email/PII coverage.
export function redactLogString(value: string) {
  return redactSecrets(value);
}

function parsePositiveInt(value: string | null, fallback: number, max: number) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1) return fallback;
  return Math.min(parsed, max);
}

function validDate(value: string | null) {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function latestDate(a: Date | null, b: Date | null) {
  if (!a) return b;
  if (!b) return a;
  return a > b ? a : b;
}

export function parseLogListParams(searchParams: URLSearchParams) {
  const limit = parsePositiveInt(searchParams.get("limit"), DEFAULT_LIMIT, MAX_LIMIT);
  const page = parsePositiveInt(searchParams.get("page"), 1, 10000);
  return {
    limit,
    page,
    skip: (page - 1) * limit,
    format: searchParams.get("format")?.trim().toLowerCase() === "csv" ? "csv" : "json"
  };
}

function escapeRegex(value: string) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function extractLogEnvironment(metadata?: Record<string, unknown> | null) {
  if (!metadata || typeof metadata !== "object") return null;
  for (const key of ["environment", "env", "stage", "deployment", "targetEnvironment"]) {
    const value = metadata[key];
    if (typeof value === "string" && value.trim()) return value.trim().slice(0, 80);
  }
  return null;
}

export function getLogDecision(log: Pick<VerificationLogListItem, "allowed" | "approvalRequired" | "reason">): LogDecision {
  if (log.allowed) return "allowed";
  if (log.approvalRequired || APPROVAL_REASON_RE.test(log.reason)) return "approval_required";
  return "denied";
}

export function buildVerificationLogQuery(
  searchParams: URLSearchParams,
  baseQuery: Record<string, unknown>,
  options: { retentionStart?: Date | null } = {}
) {
  const query: Record<string, unknown> = { ...baseQuery };
  const rawSearch = searchParams.get("search")?.trim() || searchParams.get("q")?.trim() || "";
  const smart = rawSearch ? parseSmartLogQuery(rawSearch) : null;

  const agentId =
    searchParams.get("agentId")?.trim() ||
    searchParams.get("agent")?.trim() ||
    smart?.agentId?.trim();
  const action = searchParams.get("action")?.trim() || smart?.action?.trim();
  const vendor =
    searchParams.get("vendor")?.trim() ||
    searchParams.get("resource")?.trim() ||
    smart?.vendor?.trim();
  const environment = searchParams.get("environment")?.trim() || smart?.environment?.trim();
  const requestId = searchParams.get("requestId")?.trim();
  const allowed =
    searchParams.get("allowed")?.trim() ||
    decisionToAllowed(searchParams.get("decision")?.trim()) ||
    decisionToAllowed(smart?.decision ?? null);
  const risk = searchParams.get("risk")?.trim() || smart?.risk?.trim();
  const shadowParam = searchParams.get("shadow")?.trim();
  const search = smart ? smart.freeText : rawSearch;
  const from = validDate(searchParams.get("from") ?? searchParams.get("start"));
  const to = validDate(searchParams.get("to") ?? searchParams.get("end"));
  const smartFrom =
    !from && smart?.range
      ? new Date(Date.now() - (smart.range === "24h" ? 24 : 7 * 24) * 60 * 60 * 1000)
      : null;
  const gte = latestDate(options.retentionStart ?? null, latestDate(from, smartFrom));

  if (agentId && !Object.prototype.hasOwnProperty.call(baseQuery, "agentId")) {
    query.agentId = agentId;
  }
  if (action) query.action = action;
  if (vendor) query.vendor = vendor;
  if (requestId) query.requestId = requestId;
  if (allowed === "true") query.allowed = true;
  if (allowed === "false") query.allowed = false;
  if (allowed === "approval") { query.allowed = false; query.approvalRequired = true; }
  if (risk && RISKS.has(risk)) query.risk = risk;
  if (shadowParam === "true") query.shadow = true;
  // `{ shadow: null }` rather than `{ $exists: false }`: Mongo's null equality
  // also matches documents where the field is absent, and the Postgres adapters
  // map a literal null to `IS NULL` — whereas `$exists` throws "Unsupported
  // filter operator" there. `shadow` is `NOT NULL DEFAULT false` in Postgres,
  // so the null branch only ever matches legacy Mongo documents.
  if (shadowParam === "false") query.$or = [{ shadow: false }, { shadow: null }];
  if (environment) {
    query.$and = [
      ...(Array.isArray(query.$and) ? query.$and : []),
      {
        $or: [
          { "metadata.environment": new RegExp(`^${escapeRegex(environment)}$`, "i") },
          { "metadata.env": new RegExp(`^${escapeRegex(environment)}$`, "i") },
          { "metadata.stage": new RegExp(`^${escapeRegex(environment)}$`, "i") }
        ]
      }
    ];
  }
  if (search) {
    const pattern = new RegExp(escapeRegex(search), "i");
    query.$and = [
      ...(Array.isArray(query.$and) ? query.$and : []),
      { $or: SEARCHABLE_FIELDS.map((field) => ({ [field]: pattern })) }
    ];
  }
  if (gte || to) query.createdAt = {
    ...(gte ? { $gte: gte } : {}),
    ...(to ? { $lte: to } : {})
  };

  return query;
}

function decisionToAllowed(decision?: string | null) {
  if (!decision) return null;
  if (decision === "allowed") return "true";
  if (decision === "denied") return "false";
  if (decision === "approval" || decision === "approval_required" || decision === "requires_approval") {
    return "approval";
  }
  return null;
}

export function calculateVerificationLogSummary(logs: VerificationLogListItem[]): VerificationLogSummary {
  const deniedByAction = new Map<string, number>();
  const byVendor = new Map<string, number>();
  const summary: VerificationLogSummary = {
    total: logs.length,
    allowed: 0,
    denied: 0,
    highRisk: 0,
    approvalRequired: 0,
    topDeniedAction: null,
    topVendor: null
  };

  for (const log of logs) {
    if (log.allowed) summary.allowed += 1;
    else {
      summary.denied += 1;
      deniedByAction.set(log.action, (deniedByAction.get(log.action) ?? 0) + 1);
    }
    if (log.risk === "high") summary.highRisk += 1;
    if (log.approvalRequired || /requires approval|approval required|approval before execution/i.test(log.reason)) {
      summary.approvalRequired += 1;
    }
    if (log.vendor) byVendor.set(log.vendor, (byVendor.get(log.vendor) ?? 0) + 1);
  }

  summary.topDeniedAction = topKey(deniedByAction);
  summary.topVendor = topKey(byVendor);
  return summary;
}

function topKey(values: Map<string, number>) {
  let top: string | null = null;
  let count = 0;
  for (const [key, value] of values) {
    if (value > count) {
      top = key;
      count = value;
    }
  }
  return top;
}

/**
 * Compute dashboard log summary via repository aggregateStats (Mongo pipeline or
 * Postgres equivalent). Falls back to in-process calculation when needed.
 */
export async function getVerificationLogSummaryAgg(
  query: Record<string, unknown>,
  limit = 1000
): Promise<VerificationLogSummary> {
  const aggregated = await aggregateStats(query, limit);
  if (aggregated) {
    return aggregated;
  }

  // Fallback: fetch documents and compute summary in-process.
  const logs = (await findLogs(query, {
    sort: { createdAt: -1 },
    limit
  })) as unknown as VerificationLogListItem[];
  return calculateVerificationLogSummary(logs);
}

export async function withAgentNames(
  logs: VerificationLogListItem[],
  scope: { developerUserId?: string; accountId?: string }
) {
  const agentIds = Array.from(new Set(logs.map((log) => log.agentId))).filter(Boolean);
  if (!agentIds.length) return logs.map(sanitizeVerificationLog);

  const query: Record<string, unknown> = { agentId: { $in: agentIds } };
  if (scope.developerUserId) query.developerUserId = scope.developerUserId;
  if (scope.accountId) query.accountId = scope.accountId;
  const agents = await listAgents(query, { select: "-_id agentId name" });
  const names = new Map(agents.map((agent) => [agent.agentId, agent.name]));
  return logs.map((log) => sanitizeVerificationLog({
    ...log,
    agentName: names.get(log.agentId) ?? null,
    environment: log.environment ?? extractLogEnvironment(log.metadata ?? null)
  }));
}

function sanitizeMetadata(metadata?: Record<string, unknown> | null) {
  if (!metadata || typeof metadata !== "object") return metadata ?? null;
  const sanitized: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(metadata)) {
    if (typeof value === "string") {
      sanitized[key] = redactLogString(value);
    } else if (Array.isArray(value)) {
      sanitized[key] = value.map((item) => (typeof item === "string" ? redactLogString(item) : item));
    } else if (value && typeof value === "object") {
      sanitized[key] = sanitizeMetadata(value as Record<string, unknown>);
    } else {
      sanitized[key] = value;
    }
  }
  return sanitized;
}

export function sanitizeVerificationLog(log: VerificationLogListItem): VerificationLogListItem {
  const metadata = sanitizeMetadata(log.metadata ?? null);
  const environment = log.environment ?? extractLogEnvironment(metadata);
  return {
    ...log,
    requestId: redactLogString(log.requestId),
    accountId: log.accountId ? redactLogString(log.accountId) : log.accountId,
    developerUserId: log.developerUserId ? redactLogString(log.developerUserId) : log.developerUserId,
    agentId: redactLogString(log.agentId),
    agentName: log.agentName ? redactLogString(log.agentName) : log.agentName,
    permissionId: log.permissionId ? redactLogString(log.permissionId) : log.permissionId,
    action: redactLogString(log.action),
    vendor: log.vendor ? redactLogString(log.vendor) : log.vendor,
    environment: environment ? redactLogString(environment) : environment,
    reason: redactLogString(log.reason),
    decision: getLogDecision(log),
    metadata,
    approvalId: log.approvalId ? redactLogString(log.approvalId) : log.approvalId ?? null
  };
}

export type DenyReceiptData = {
  decision: "denied" | "approval_required";
  agent: string;
  action: string;
  resource: string | null;
  risk: string;
  reason: string;
  permissionId: string | null;
  requestId: string;
  timestamp: string;
};

export function buildReceiptData(log: VerificationLogListItem): DenyReceiptData {
  const isApproval = log.approvalRequired || APPROVAL_REASON_RE.test(log.reason);
  const decision = isApproval ? "approval_required" : "denied";
  const ts = log.createdAt instanceof Date
    ? log.createdAt.toISOString()
    : (typeof log.createdAt === "string" ? log.createdAt : new Date().toISOString());
  return {
    decision,
    agent: redactLogString(log.agentName || log.agentId),
    action: redactLogString(log.action),
    resource: log.vendor ? redactLogString(log.vendor) : null,
    risk: log.risk,
    reason: redactLogString(log.reason),
    permissionId: log.permissionId ? redactLogString(log.permissionId) : null,
    requestId: redactLogString(log.requestId),
    timestamp: ts
  };
}

export function formatReceiptText(data: DenyReceiptData): string {
  const decisionLabel = data.decision === "approval_required" ? "Approval Required" : "Denied";
  const lines = [
    "Blocked Action",
    `Agent:      ${data.agent}`,
    `Action:     ${data.action}`,
  ];
  if (data.resource) lines.push(`Resource:   ${data.resource}`);
  lines.push(`Decision:   ${decisionLabel}`);
  lines.push(`Reason:     ${data.reason}`);
  lines.push(`Risk:       ${data.risk}`);
  if (data.permissionId) lines.push(`Policy:     ${data.permissionId}`);
  lines.push(`Request ID: ${data.requestId}`);
  lines.push(`Time:       ${data.timestamp}`);
  return lines.join("\n");
}

export async function withApprovalLinks(
  logs: VerificationLogListItem[],
  scope: { accountId: string }
) {
  const requestIds = logs
    .filter((log) => !log.allowed && (log.approvalRequired || APPROVAL_REASON_RE.test(log.reason)))
    .map((log) => log.requestId)
    .filter(Boolean);
  if (!requestIds.length) return logs;

  const approvals = await findApprovals({
    accountId: scope.accountId,
    requestId: { $in: requestIds }
  });

  const byRequest = new Map(
    (approvals as Array<{ approvalId: string; requestId: string }>).map((item) => [
      item.requestId,
      item.approvalId
    ])
  );
  return logs.map((log) => ({
    ...log,
    approvalId: byRequest.get(log.requestId) ?? log.approvalId ?? null
  }));
}

export function logsToCsv(logs: VerificationLogListItem[]) {
  const headers = [
    "createdAt",
    "shadow",
    "decision",
    "approvalRequired",
    "risk",
    "agentId",
    "agentName",
    "action",
    "vendor",
    "environment",
    "amount",
    "reason",
    "requestId",
    "approvalId"
  ];
  const rows = logs.map((log) => [
    stringifyDate(log.createdAt),
    log.shadow ? "true" : "false",
    getLogDecision(log),
    log.approvalRequired ? "true" : "false",
    log.risk,
    log.agentId,
    log.agentName ?? "",
    log.action,
    log.vendor ?? "",
    log.environment ?? extractLogEnvironment(log.metadata ?? null) ?? "",
    log.amount ?? "",
    log.reason,
    log.requestId,
    log.approvalId ?? ""
  ]);
  return [headers, ...rows].map((row) => row.map(csvCell).join(",")).join("\n");
}

function stringifyDate(value?: Date | string) {
  if (!value) return "";
  return value instanceof Date ? value.toISOString() : value;
}

function csvCell(value: unknown) {
  const text = String(value ?? "");
  return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}
