---
"@javargasm/pi-kiro": patch
---

Fix provider name mismatch that hid all models from pi's model selector. The registered provider name ("kiro AWS") did not match the auth.json key ("kiro"), causing pi's AuthStorage to fail credential lookup.
