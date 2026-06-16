---
"@javargasm/pi-kiro": patch
---

Align stream request headers with real Kiro CLI traffic. Updates User-Agent to match the current AWS SDK Rust client format, sets `Accept: */*` and `Accept-Encoding: gzip`, bumps `amz-sdk-request` max attempts to 3, adds `Pragma`/`Cache-Control: no-cache`, and removes the `x-amzn-kiro-agent-mode` header that is no longer sent by the real client.
