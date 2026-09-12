import { describe, expect, it, vi } from "vitest";

// Scoped to its own file: mocking `node:sqlite` here would otherwise
// defeat the sibling suite's "no native driver available" assumption.
// Vite does not externalize `node:sqlite` (it strips the `node:` prefix
// and `sqlite` is absent from `module.builtinModules`), so the real
// module never loads under vitest — the factory below stands in for it.
const prepare = vi.fn();
const close = vi.fn();
const databaseSyncCtor = vi.fn();

vi.mock("node:sqlite", () => ({
  DatabaseSync: class {
    constructor(path: string, options?: { readOnly?: boolean }) {
      databaseSyncCtor(path, options);
    }
    prepare = prepare;
    exec = vi.fn();
    close = close;
  },
}));

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return { ...actual, existsSync: vi.fn().mockReturnValue(true), readFileSync: vi.fn() };
});

import { importFromKiroCli } from "../src/kiro-cli-sync";

describe("node:sqlite driver", () => {
  it("reads the kiro-cli DB on a plain Node runtime and opens it read-only", async () => {
    prepare.mockImplementation((sql: string) => ({
      all: () =>
        sql.includes("auth_kv")
          ? [
              {
                key: "kirocli:odic:device-registration",
                value: JSON.stringify({ client_id: "CID", client_secret: "SEC" }),
              },
              {
                key: "kirocli:odic:token",
                value: JSON.stringify({
                  accessToken: "AT",
                  refreshToken: "RT",
                  region: "us-east-1",
                }),
              },
            ]
          : [],
      get: () => ({
        value: JSON.stringify({
          arn: "arn:aws:codewhisperer:eu-central-1:000000000000:profile/P",
        }),
      }),
      run: vi.fn(),
    }));

    const creds = await importFromKiroCli();

    expect(creds).toMatchObject({
      accessToken: "AT",
      refreshToken: "RT",
      authMethod: "idc",
      source: "kiro-cli-db",
      tokenKey: "kirocli:odic:token",
      clientId: "CID",
      clientSecret: "SEC",
      // Region comes from the active profile ARN, not the token row.
      region: "eu-central-1",
    });
    // `readonly` must be translated to node:sqlite's `readOnly` spelling,
    // otherwise the import silently opens the user's DB read-write.
    expect(databaseSyncCtor).toHaveBeenCalledWith(
      expect.stringContaining("data.sqlite3"),
      { readOnly: true },
    );
    expect(close).toHaveBeenCalled();
  });
});
