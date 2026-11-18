"""A12: account enumeration (docs/threat_model.md, FR-C9, NFR-1).

Attacker model: the attacker has a list of usernames and wants to know which ones have an
account, from the response text, the status code, or the response time.

Surfaces tested (each against a service started for the test):
    login             200 requests for existing accounts and 200 for unknown names (FR-C9),
                      all with a wrong password
    registration      200 taken names and 200 new names, timing and content separately
    recovery          200 wrong codes for existing accounts and 200 for unknown names
    passkey options   the options the service returns for a username

Pass rule (FR-C9): same status code and message in both groups, and the medians of the two
response-time groups differ by less than 5 ms with overlapping 95% bootstrap intervals.
Times are measured by the client (what an attacker sees), in milliseconds, with a warm-up
and with the two groups interleaved so a slow moment hits both.

Expected results, written down before the tests were run (threat model, row A12):
    login, registration, recovery   blocked (same answers, same time)
    passkey options                 blocked (the threat model says the response does not
                                    reveal whether the name exists)

Rate limits (FR-A7, FR-A1: 20 failed logins per address, 20 registrations per address in 15
minutes) would stop 400 requests from one address. The service is not changed. Instead the
test client connects from many loopback source addresses (127.x.0.y), so the service sees
many different addresses, like an attacker with a pool of addresses. Each request goes to a
different account, so the 5-failures-per-account limit is not reached either.
"""
import time
from contextlib import ExitStack, contextmanager

import httpx
import pytest

from harness import stats

from .conftest import PASSWORD, new_username, register
from .server import running_service
from .test_origin_mismatch import enrol_passkey

GROUP_SIZE = 200
WARM_UP = 5
ADDRESSES = 41          # odd, so the alternating groups do not always use the same addresses
MAX_MEDIAN_DIFFERENCE_MS = 5.0


@contextmanager
def address_pool(service, second_octet: int):
    """Clients that connect from 127.<second_octet>.0.1 ... .ADDRESSES. Each test uses its own
    second octet, so the limits counted per address start from zero in every test."""
    with ExitStack() as stack:
        clients = []
        for i in range(ADDRESSES):
            transport = httpx.HTTPTransport(local_address=f"127.{second_octet}.0.{i + 1}")
            c = stack.enter_context(httpx.Client(base_url=service.base_url, transport=transport, timeout=30))
            c.get("/health")        # open the connection now, so its set-up time is not measured
            clients.append(c)
        yield clients


def timed(call) -> tuple[httpx.Response, float]:
    start = time.perf_counter()
    response = call()
    return response, (time.perf_counter() - start) * 1000


def interleaved_run(clients, make_a, make_b):
    """Sends GROUP_SIZE requests of kind A and of kind B, alternating, each from the next address.
    make_a(client, i) and make_b(client, i) send request number i of their kind.
    Returns (responses_a, times_a, responses_b, times_b) without the warm-up."""
    out = {"a": ([], []), "b": ([], [])}
    n = 0
    for i in range(-WARM_UP, GROUP_SIZE):
        for key, make in (("a", make_a), ("b", make_b)):
            response, ms = timed(lambda: make(clients[n % len(clients)], i))
            n += 1
            if i >= 0:
                out[key][0].append(response)
                out[key][1].append(ms)
    return out["a"][0], out["a"][1], out["b"][0], out["b"][1]


def same_answers(a, b) -> tuple[bool, str]:
    seen = {(r.status_code, r.text) for r in a} | {(r.status_code, r.text) for r in b}
    return len(seen) == 1, f"answers seen: {sorted(seen)[:3]}"


def timing_verdict(times_a: list[float], times_b: list[float]) -> tuple[bool, str]:
    sa, sb = stats.summarize(times_a), stats.summarize(times_b)
    difference = abs(sa.median - sb.median)
    overlap = stats.intervals_overlap((sa.ci_low, sa.ci_high), (sb.ci_low, sb.ci_high))
    ok = difference < MAX_MEDIAN_DIFFERENCE_MS and overlap
    detail = (f"median A {sa.median:.1f} ms [{sa.ci_low:.1f}, {sa.ci_high:.1f}], "
              f"median B {sb.median:.1f} ms [{sb.ci_low:.1f}, {sb.ci_high:.1f}], "
              f"difference {difference:.2f} ms, intervals overlap: {overlap}")
    return ok, detail


def register_accounts(client_pool, count: int) -> list[str]:
    names = []
    for i in range(count):
        name = new_username()
        register(client_pool[i % len(client_pool)], name)
        names.append(name)
    return names


def test_login_does_not_reveal_which_accounts_exist(report):
    with running_service() as svc, address_pool(svc, 11) as pool:
        existing = register_accounts(pool, GROUP_SIZE + WARM_UP)
        unknown = [new_username() for _ in range(GROUP_SIZE + WARM_UP)]

        def login(names):
            return lambda c, i: c.post("/session/login/password",
                                       json={"username": names[i + WARM_UP], "password": "wrong password!"})
        a, ta, b, tb = interleaved_run(pool, login(existing), login(unknown))

    same, answers = same_answers(a, b)
    quick, timing = timing_verdict(ta, tb)
    actual = "blocked" if same and quick else "succeeded"
    assert report("enumeration_login", "password", "blocked", actual,
                  f"A = existing, B = unknown, wrong password; same answers: {same} ({answers}); {timing}")
    assert actual == "blocked"


@pytest.mark.xfail(reason="finding: registering a new name is about 3 ms slower than a taken name (the new "
                          "account is written to the database), and the 95% intervals do not overlap. Issue #29.")
def test_registration_timing_does_not_reveal_taken_names(report):
    with running_service() as svc, address_pool(svc, 12) as pool:
        taken = register_accounts(pool, GROUP_SIZE + WARM_UP)

        def attempt(names):
            return lambda c, i: c.post("/auth/register", json={"username": names[i + WARM_UP], "password": PASSWORD})
        fresh = [new_username() for _ in range(GROUP_SIZE + WARM_UP)]
        a, ta, b, tb = interleaved_run(pool, attempt(taken), attempt(fresh))

    quick, timing = timing_verdict(ta, tb)
    actual = "blocked" if quick else "succeeded"
    assert report("enumeration_registration_timing", "password", "blocked", actual,
                  f"A = taken name, B = new name; {timing}")
    assert actual == "blocked"


@pytest.mark.xfail(reason="finding: registration of a taken name answers 400 'Registration failed.' while a new "
                          "name answers 201, so the answer itself shows whether a name is taken (no e-mail "
                          "confirmation step to hide it). Design decision pending, no issue filed.")
def test_registration_answer_does_not_reveal_taken_names(report):
    with running_service() as svc, address_pool(svc, 13) as pool:
        taken = register_accounts(pool, 10)
        fresh = [new_username() for _ in range(10)]
        a = [pool[i].post("/auth/register", json={"username": n, "password": PASSWORD}) for i, n in enumerate(taken)]
        b = [pool[i].post("/auth/register", json={"username": n, "password": PASSWORD}) for i, n in enumerate(fresh)]

    same, answers = same_answers(a, b)
    actual = "blocked" if same else "succeeded"
    assert report("enumeration_registration_content", "password", "blocked", actual,
                  f"A = taken name, B = new name; same answers: {same} ({answers})")
    assert actual == "blocked"


@pytest.mark.xfail(reason="finding: recovery for an existing account is about 0.3 to 0.4 ms slower than for an "
                          "unknown name (one more database query); the difference is under 5 ms but the 95% "
                          "intervals do not overlap (FR-C9 rule). Module B (app/recovery), Issue #30.")
def test_recovery_does_not_reveal_which_accounts_exist(report):
    with running_service() as svc, address_pool(svc, 14) as pool:
        existing = register_accounts(pool, GROUP_SIZE + WARM_UP)
        unknown = [new_username() for _ in range(GROUP_SIZE + WARM_UP)]

        def start(names):
            return lambda c, i: c.post("/recovery/start", json={"username": names[i + WARM_UP], "code": "AAAA-BBBB"})
        a, ta, b, tb = interleaved_run(pool, start(existing), start(unknown))

    same, answers = same_answers(a, b)
    quick, timing = timing_verdict(ta, tb)
    actual = "blocked" if same and quick else "succeeded"
    assert report("enumeration_recovery", "password", "blocked", actual,
                  f"A = existing, B = unknown, wrong recovery code; same answers: {same} ({answers}); {timing}")
    assert actual == "blocked"


@pytest.mark.xfail(reason="finding: /auth/webauthn/login/options lists the credential id of an account's "
                          "passkeys (allowCredentials) and answers with an empty list for unknown names, so the "
                          "response shows which usernames have a passkey. Issue #28.")
def test_passkey_options_do_not_reveal_which_accounts_have_a_passkey(report):
    with running_service() as svc, address_pool(svc, 15) as pool:
        owner = new_username()
        register(pool[0], owner)
        enrol_passkey(svc, pool[0], owner)
        no_passkey = new_username()
        register(pool[1], no_passkey)

        def options(client, name):
            return client.post("/auth/webauthn/login/options", json={"username": name}).json()["options"]
        shapes = {
            "has passkey": len(options(pool[2], owner)["allowCredentials"]),
            "no passkey": len(options(pool[3], no_passkey)["allowCredentials"]),
            "unknown": len(options(pool[4], new_username())["allowCredentials"]),
        }

    leak = len(set(shapes.values())) > 1
    actual = "succeeded" if leak else "blocked"
    assert report("enumeration_passkey_options", "passkey", "blocked", actual,
                  f"number of allowed credentials in the options: {shapes}")
    assert actual == "blocked"
