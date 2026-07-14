---
"@javargasm/pi-kiro": patch
---

Fix disk cache write failure on fresh installs (missing mkdirSync), deduplicate aliased imports, use log.warn instead of console.warn, remove any types from ExtensionAPI, and add @ts-ignore for bun:sqlite TS7 compatibility.
