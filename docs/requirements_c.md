# Module C requirements: attack suite and evaluation framework

Status: **written on 4 November 2026** as catch-up for the Week 4 task ("requirements for the attack suite and the evaluation framework"). The team's requirements specification (revised version) defines FR-C1 to FR-C13 and the rules in its Sections 5 to 8. This document does not replace it. It states, for each requirement of Module C, how it is verified, in which semester it is due, and its status in this repository today. The specification file itself is not stored in the repository; this document quotes only what Module C needs.

All attacks run only against the team's own service on the team's own machines.

## 1. Requirements

| ID | Requirement (short) | How it is verified | Sem | Status on 4 Nov 2026 |
|---|---|---|---|---|
| FR-C1 | Every attack is an automated test that runs in CI and reports a result for each method | `pytest attacks` shows one result per attack and method; the outcomes are also written to `results/attack_results.jsonl` | 1 | started: replay test (Week 6) |
| FR-C2 | Phishing: a look-alike page on another origin relays the login in real time | test records whether the attacker obtains a valid session, per method | 1 | not started |
| FR-C3 | Credential stuffing (1,000 generated pairs) and brute force against the FR-A7 limits | guesses that get through per hour, per method | 1 | not started |
| FR-C4 | Each flow is run 20 times per method after one warm-up run; friction and server timing are saved | result file has exactly 20 measured runs per flow and method | 1 | statistics and log reader done (Week 5); browser driver not started |
| FR-C5 | Fatigue: an attacker who knows the password starts 20 logins in 10 minutes | what reaches the user, and whether any attempt succeeds without the user entering a code or using their own device | 1 | not started |
| FR-C6 | CSRF: a page on another origin sends logout-all, add credential and change recovery settings with the user's cookie | all three requests rejected, nothing changes | 1 | not started |
| FR-C7 | OTP relay, session hijacking, session fixation | outcome per method against the expectation in `docs/threat_model.md` | 2 | OTP replay part started (Week 6) |
| FR-C8 | Downgrade: make a passkey user log in with a weaker method | outcome under each policy | 2 | not started |
| FR-C9 | Enumeration on content and timing (200 + 200 login requests) | identical messages and codes; medians within 5 ms with overlapping 95% intervals | 2 | not started |
| FR-C10 | Recovery attacks on both designs | which attacks succeed, per design | 2 | not started |
| FR-C11 | Load test with 1, 10, 25 and 50 concurrent logins (Locust) | throughput, median, p95 and memory per level | 2 | not started |
| FR-C12 | Campaign repeated under three policies | results for all three policies | 2 | not started |
| FR-C13 | Comparison and recommendation | final report tables, each linked to measured results | 2 | not started |

## 2. Rules that apply to every Module C requirement

These come from the specification (Sections 5, 7 and 8) and from the course rules. They are testable, so each has a way to check it.

| Rule | Source | How it is checked |
|---|---|---|
| Module C talks to the service only through the HTTP API and the two log files; it imports nothing from Module A or B | NFR-7 | `tests_c/test_independence.py` scans `harness/`, `attacks/` and `tests_c/` for imports of `app` |
| A flow is run 20 times per method after one warm-up run that is not counted | Section 7.2 | `harness.stats` and the campaign script; the result file has exactly 20 runs |
| Median, 95th percentile (nearest rank) and a 95% bootstrap interval of the median with 10,000 resamples; two methods differ only if their intervals do not overlap | Section 7.2 | known-answer tests in `tests_c/test_stats.py` |
| Step rule: button click, one filled field, QR scan, one authenticator prompt, opening the TOTP app are 1 step each; page loads and waiting are not steps | Section 7.1 | `harness.logs` counts `step` events; expected counts are 3 (password), 6 (password + TOTP), 2 (passkey), taken from the rule |
| The two log formats (friction, server timing) are the interface with Module B; a contract test checks a sample | Section 8 | `tests_c/test_logs.py` validates a sample and the lines the service writes |
| Every result file records the commit hash, the parameters and the machine specification | NFR-5 | `harness.results.run_metadata()`, tested |
| Random seeds are fixed | NFR-5 | bootstrap seed is a parameter with a default, tested for repeatability |
| Results are produced by a script, never typed by hand | course rules | tables come from `results/*.jsonl` through scripts |
| Every expected outcome is written before the test is run; a result that differs is a finding, written up as an issue, and the test is marked `xfail(reason="Issue #N")` while it is open | `docs/threat_model.md` | review of the attack tests |
| Each check has a negative test; a valid case being accepted alone proves nothing | course rules | each attack test has a control that shows the attack works where it should |

## 3. Mapping from the threat model to the requirements

`docs/threat_model.md` has twelve attacks (A1 to A12). The specification groups them under FR-C2 to FR-C10:

| Threat model | Requirement |
|---|---|
| A1 phishing relay | FR-C2 |
| A2 replay of a one-time code | FR-C7 (OTP relay) and the Week 6 task of the project plan |
| A3 origin or RP ID mismatch | FR-C2 (passkey column) and the Week 8 task |
| A4 session fixation, A5 token reuse, A6 session hijacking | FR-C7 |
| A7 brute force and credential stuffing | FR-C3 |
| A8 fatigue | FR-C5 |
| A9 CSRF | FR-C6 |
| A10 downgrade | FR-C8 |
| A11 recovery bypass | FR-C10 |
| A12 account enumeration | FR-C9 |

## 4. Open decisions

1. **Fatigue (FR-C5).** The specification asks whether to test it as written or to add a simulated push approval (Section 13 of the specification). The expected result in `docs/threat_model.md` assumes the test as written: no method sends a prompt to a device the attacker does not control, so the measurable effect is the rate-limit lockout of the victim. The result will be reported with that reading.
2. **Passkey replay in the attack suite.** A passkey test needs a software authenticator. Module A has one in `tests/`, but Module C may not import it (NFR-7). Module C will write its own for the passkey attacks (Week 8).
3. **Enumeration test needs a registration timing fix.** Issue #6 (registration skips Argon2id for an existing name) will make FR-C9 fail on registration until it is fixed.
