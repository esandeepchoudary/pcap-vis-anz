---
sidebar_position: 22
sidebar_label: "Security"
title: "Security model"
description: "Accounts, roles, engagement isolation, request protections, untrusted data handling and deployment advice."
---

# Security model

**Accounts.** Local accounts with argon2id password hashes (minimum 10 characters), server-side sessions (only
a hash of the session token is stored), sign-in throttling, and sessions revoked when a user's role, password or
status changes. The session cookie is `HttpOnly`, `SameSite=Strict`, and `Secure` with `PCAPVIS_COOKIE_SECURE`.

**Engagement isolation.** Every engagement route checks membership; someone who isn't a member gets "not found",
never "forbidden", so engagement names don't leak. Engagement roles are capped by the user's account role.
Every id in a request (capture, asset, zone, conduit, finding) is checked to belong to that engagement. A test
walks every API operation to keep this true as the API grows.

**Request protections.** State-changing requests must carry a custom header that browsers can't add cross-site
(CSRF protection); JSON bodies are capped; uploads are streamed with a size limit and format check; a strict
Content-Security-Policy, `X-Frame-Options: DENY`, `nosniff`, `no-referrer`, Permissions-Policy and (over HTTPS)
HSTS are sent.

**Untrusted data.** Everything in a capture is attacker-controllable. Hostnames, device strings and HTTP data
are shown as text (never HTML), and neutralised in every export (no spreadsheet formulas, no markup in draw.io
or SVG, escaped HTML, control characters stripped). Files extracted from traffic are always downloaded, never
rendered. Imported bundles are validated strictly (paths, sizes, compression ratios, hashes, every field)
and a failed import leaves nothing behind.

**Packet inspector.** Display filters are passed to tshark as a single argument (no shell), run with time and
output limits, and at most three run at once. It's available to editors only because raw packets contain
unmasked secrets; credentials elsewhere are masked until revealed.

**Deployment advice.** Serve over HTTPS ([Team server](deployment.md#https)), keep the server on a management
network, remove the first-admin password from the environment after setup, and treat `.pcapvis` bundles and
backups as confidential: they contain client network data and possibly credentials.
