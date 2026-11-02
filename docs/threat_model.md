# Threat model and expected attack results (Module C)

Status: **draft, written on 3 November 2026 as catch-up for the Week 2 task** ("study the threat model: phishing, replay, session fixation, fatigue"). It is based on the project description, the supervisor's requirements review, and the design of the service as it is in the repository today (Modules A and B). Every entry in the "Expected" column is a **statement made before the test is written**. The test then confirms or refutes it, and a refuted expectation is a finding, not a failure of the document. Nothing here has been measured yet.

All attacks run only against the team's own service on the team's own machines. No third-party system is tested.

Outcome values are those of `docs/metrics.md`: `blocked`, `succeeded`, `not_applicable`, `error`. Methods: **P** password, **T** password + one-time code (TOTP), **K** passkey (WebAuthn).

## 1. Attacker model

The attacker can: read and send any network request to the service, run a look-alike login page that a victim visits, obtain a credential the victim typed into that page (password, one-time code), copy a session cookie (for example from a stolen device), and try many guesses. The attacker cannot: read the victim's device memory, break the cryptography, or touch the database.

## 2. Attacks and expected results

| # | Attack | What the test does | P | T | K | Why (design reference) |
|---|---|---|---|---|---|---|
| A1 | Phishing: relay of what the victim typed | Fake page captures the credentials and the attacker logs in at the real service | succeeded | succeeded if relayed within the code window | blocked | A password and a code are valid wherever they are sent. A passkey signature covers the origin and the relying party ID, so the real service rejects a response made for another origin (FR-A5 checks 5 and 6). |
| A2 | Replay of a captured credential | Re-send a login that was captured earlier | succeeded | blocked after first use | blocked | A password can be reused. A one-time code is accepted once (`last_used_step`) and the previous window only once. A passkey challenge is single use (`consume_challenge`) and the counter must not go backwards. |
| A3 | Origin / relying party mismatch | Send a passkey response created for another origin or RP ID | not_applicable | not_applicable | blocked | Only WebAuthn has an origin. Run with the browser virtual authenticator. |
| A4 | Session fixation | Plant a session ID, let the victim log in, use the planted ID | blocked | blocked | blocked | A new random session ID is issued at login and the old one is revoked (FR-B4). The result does not depend on the method. |
| A5 | Token reuse after logout or revocation | Use a session cookie after logout, logout-all, expiry, or recovery | blocked | blocked | blocked | Revoked and expired sessions are rejected on every protected endpoint (FR-B2, FR-B3). |
| A6 | Session hijacking (stolen cookie) | Use a copied cookie from another client | succeeded | succeeded | succeeded | The session is a bearer cookie with no binding to the device or address. The protection is time (30 minutes idle, 12 hours total) and revocation, so this is a **residual risk of the session design**, the same for all three methods. |
| A7 | Brute force and credential stuffing | Many guesses for one account, and many accounts from one address | blocked after the limit | blocked after the limit | not_applicable (no secret to guess) | 5 failures per account and 20 per address in 15 minutes (FR-A7). The count of guesses before the block is the result. |
| A8 | Fatigue: repeated prompts | Attacker who knows the password starts many logins | blocked (no prompt) | blocked (no prompt) | blocked (no prompt) | No method sends an approval prompt to a device the attacker does not control. The user types a code or touches a key on the device that started the login. The measurable effect is the rate limit, which can lock the victim out (a denial of service). |
| A9 | Cross-site request forgery | Send a state-changing request from another origin without the CSRF token | blocked | blocked | blocked | Protected routes need the CSRF token and the cookie is SameSite=Lax (FR-B1). Login and recovery routes have no cookie to protect, so a login CSRF is not blocked there (low impact; Module C reports it). |
| A10 | Downgrade | Ask for a weaker method than the strongest the account has | succeeded under `permissive`; blocked under `passkey_only` | succeeded under `permissive`; blocked under `passkey_only` | blocked | The policy file decides which methods may log in (FR-A11). Semester II task. |
| A11 | Recovery-based bypass | Use a stolen recovery code to enter | succeeded after the waiting period if the owner does not cancel | same | same | A code starts a 24-hour wait with a notification to the owner; wrong codes are rate limited (FR-B7, FR-B8). Recovery is the weakest path by design and is the same for every method. |
| A12 | Account enumeration | Learn whether an account exists from the response text and from the response time | login: blocked; registration: succeeded by time | same | same | Messages are the same for unknown user and wrong password. Login computes a dummy hash for unknown users, registration does not (Issue #6). Recovery returns the same error for unknown users and wrong codes. |

## 3. What is not covered

- Malware on the victim's device, a compromised browser, or attacks on the database or the server host.
- Real-world phishing kits. A1 is run against the team's own look-alike page only.
- Attacks on the hardware of a physical security key (not used in this project).

## 4. How this feeds the rest of the work

Each row becomes one or more tests in `attacks/`, each test names its expected result, and each result goes into the results table that a script produces. A row whose result differs from "Expected" is written up as an issue (as for Issues #5, #6, #7, #11 to #14) and, while it is open, marked `xfail(reason="Issue #N")` so CI stays green and the finding stays on record.
