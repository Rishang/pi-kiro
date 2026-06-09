---
"@javargasm/pi-kiro": patch
---

Post-release hardening: type safety, Node engine, coverage gate, and release docs.

- Remove all `as unknown as` casts from `src/extension.ts` (was 4). The
  model-config types are now aligned so `kiroModels` flows into the provider
  config and `modifyModels` stamps `Model<Api>` values without casts —
  satisfying the project's "no type casts in extension.ts" constraint.
- Declare `engines.node: ">=20"` to fail fast on unsupported Node versions.
- Add a coverage gate: `@vitest/coverage-v8` with floor thresholds
  (statements/lines 75%, branches 65%, functions 80%) wired into CI via a
  new `test:coverage` script. Current offline coverage is ~81% lines.
- Add `RELEASING.md` documenting the Changesets + OIDC flow and the release
  gotchas (GITHUB_TOKEN for changelog links, workflow-must-be-on-master for
  tag triggers, new-scope bootstrap with `--provenance=false`, spent tags).
