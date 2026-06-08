// Kiro CLI credential sync — import tokens from Kiro IDE's local SQLite DB.
//
// Kiro IDE stores auth credentials in ~/.kiro/db/kiro.db (macOS/Linux) or
// %APPDATA%\kiro\db\kiro.db (Windows). This module reads that DB in readonly
// mode and returns parsed credentials compatible with our KiroCredentials type.
//
// This enables zero-friction login: if the user already has Kiro IDE installed
// and logged in, pi-kiro can import the credentials without device-code flow.

import { homedir } from "node:os";
import { join } from "node:path";
import { existsSync } from "node:fs";
import { log } from "./debug";

export interface KiroCliCredentials {
  accessToken: string;
  refreshToken: string;
  clientId?: string;
  clientSecret?: string;
  region: string;
  profileArn?: string;
  authMethod: "idc" | "desktop";
  email?: string;
}

/** Platform-specific path to Kiro IDE's SQLite database. */
function getKiroDbPath(): string {
  const home = homedir();
  if (process.platform === "win32") {
    return join(
      process.env.APPDATA || join(home, "AppData", "Roaming"),
      "kiro",
      "db",
      "kiro.db",
    );
  }
  return join(home, ".kiro", "db", "kiro.db");
}

/** Safely parse JSON, returning null on failure. */
function safeJsonParse(value: unknown): any {
  if (typeof value !== "string") return null;
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

/**
 * Recursively search a nested object for clientId + clientSecret.
 * Kiro's device-registration blob nests these at varying depths.
 */
function findClientCreds(obj: any): { clientId?: string; clientSecret?: string } {
  if (!obj || typeof obj !== "object") return {};
  if (typeof obj.clientId === "string" && typeof obj.clientSecret === "string") {
    return { clientId: obj.clientId, clientSecret: obj.clientSecret };
  }
  for (const key of Object.keys(obj)) {
    const result = findClientCreds(obj[key]);
    if (result.clientId) return result;
  }
  return {};
}

/**
 * Extract region from an ARN string (e.g. arn:aws:codewhisperer:us-east-1:...).
 * Returns undefined if the ARN is malformed.
 */
function extractRegionFromArn(arn: string | undefined): string | undefined {
  if (!arn) return undefined;
  const parts = arn.split(":");
  if (parts.length < 6 || parts[0] !== "arn") return undefined;
  const region = parts[3];
  return region && region.length > 0 ? region : undefined;
}

/**
 * Attempt to read credentials from Kiro IDE's local database.
 *
 * Returns the first valid credential set found, or null if:
 * - Kiro IDE is not installed
 * - The database is unreadable
 * - No valid tokens are stored
 *
 * This function never throws — all errors are caught and logged.
 */
export async function importFromKiroCli(): Promise<KiroCliCredentials | null> {
  const dbPath = getKiroDbPath();
  if (!existsSync(dbPath)) {
    log.debug(`Kiro CLI DB not found at ${dbPath}`);
    return null;
  }

  try {
    // Dynamic import: try bun:sqlite first, fallback to better-sqlite3.
    // If neither is available, return null gracefully.
    let Database: any;
    try {
      // @ts-expect-error — bun:sqlite is a Bun-only built-in
      Database = (await import("bun:sqlite")).Database;
    } catch {
      try {
        Database = (await import("better-sqlite3")).default;
      } catch {
        log.debug("No SQLite driver available (need bun:sqlite or better-sqlite3)");
        return null;
      }
    }

    const db = new Database(dbPath, { readonly: true });

    // Set busy timeout to avoid SQLITE_BUSY if Kiro IDE has the DB open.
    try {
      db.run?.("PRAGMA busy_timeout = 5000") ?? db.exec?.("PRAGMA busy_timeout = 5000");
    } catch {
      // Some SQLite drivers use exec instead of run
    }

    // Read auth_kv table
    let rows: Array<{ key: string; value: string }>;
    try {
      const stmt = db.prepare("SELECT key, value FROM auth_kv");
      rows = stmt.all() as Array<{ key: string; value: string }>;
    } catch {
      log.debug("Failed to read auth_kv table from Kiro DB");
      try { db.close(); } catch { /* ignore */ }
      return null;
    }

    // Try to read active profile ARN from state table
    let activeProfileArn: string | undefined;
    try {
      const stateStmt = db.prepare("SELECT value FROM state WHERE key = ?");
      const stateRow = stateStmt.get("api.codewhisperer.profile") as any;
      const parsed = safeJsonParse(stateRow?.value);
      const arn = parsed?.arn || parsed?.profileArn || parsed?.profile_arn;
      if (typeof arn === "string" && arn.trim()) {
        activeProfileArn = arn.trim();
      }
    } catch {
      // State table might not exist — that's fine, tokens still work.
    }

    // Extract device registration credentials (clientId/clientSecret)
    const deviceRegRow = rows.find(
      (r) => typeof r?.key === "string" && r.key.includes("device-registration"),
    );
    const deviceReg = safeJsonParse(deviceRegRow?.value);
    const regCreds = deviceReg ? findClientCreds(deviceReg) : {};

    // Find token entries
    for (const row of rows) {
      if (!row.key.includes(":token")) continue;

      const data = safeJsonParse(row.value);
      if (!data) continue;

      const accessToken = data.accessToken || data.access_token;
      const refreshToken = data.refreshToken || data.refresh_token;
      if (!accessToken && !refreshToken) continue;

      const isIdc = row.key.includes("oidc") || row.key.includes("idc");
      const authMethod: "idc" | "desktop" = isIdc ? "idc" : "desktop";

      const oidcRegion = data.region || "us-east-1";
      let profileArn: string | undefined = data.profile_arn || data.profileArn;
      if (!profileArn && isIdc) {
        profileArn = activeProfileArn;
      }
      const serviceRegion = extractRegionFromArn(profileArn) || oidcRegion;

      const result: KiroCliCredentials = {
        accessToken: accessToken || "",
        refreshToken: refreshToken || "",
        region: serviceRegion,
        authMethod,
        profileArn,
        email: data.email || data.emailAddress,
      };

      // For IdC accounts, attach clientId/clientSecret from device registration
      if (isIdc && regCreds.clientId) {
        result.clientId = regCreds.clientId;
        result.clientSecret = regCreds.clientSecret;
      }

      try { db.close(); } catch { /* ignore */ }

      log.info(
        `Imported Kiro CLI credentials (method=${authMethod}, region=${serviceRegion}` +
        `${result.email ? `, email=${result.email}` : ""})`,
      );

      return result;
    }

    try { db.close(); } catch { /* ignore */ }
    log.debug("No valid token entries found in Kiro CLI DB");
    return null;
  } catch (err) {
    log.warn(`Failed to import from Kiro CLI: ${err}`);
    return null;
  }
}
