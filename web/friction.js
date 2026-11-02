// FR-B6: friction logging. Writes the events from Section 8 of the requirements and
// sends them to /metrics/events, which appends them to results/friction.jsonl.
//
// What counts as a step follows Section 7.1:
//   - a click on a button that submits or confirms: 1 step
//   - filling one input field: 1 step (counted when the field is left with a value)
//   - an authenticator prompt or opening the TOTP app happens outside the browser,
//     so Module C's harness adds those steps itself.
// Keystrokes are counted separately.

const Friction = (() => {
  // The harness can set ?run=<id> so its runs can be matched with these events
  const runId = new URLSearchParams(location.search).get("run") || `manual-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  let flow = null, method = null, t0 = 0, queue = [];
  const counted = new WeakSet();

  function push(event, detail = "") {
    if (!flow) return;
    queue.push({ run_id: runId, flow, method, event, t_ms: Math.round(performance.now() - t0), detail: String(detail).slice(0, 128) });
  }

  function flush() {
    if (!queue.length) return;
    const body = JSON.stringify({ events: queue });
    queue = [];
    if (navigator.sendBeacon) navigator.sendBeacon("/metrics/events", new Blob([body], { type: "application/json" }));
    else fetch("/metrics/events", { method: "POST", headers: { "Content-Type": "application/json" }, body, keepalive: true });
  }

  document.addEventListener("keydown", (e) => { if (e.target.tagName === "INPUT") push("keystroke", e.target.id); });
  document.addEventListener("change", (e) => {
    const el = e.target;
    if (el.tagName === "INPUT" && el.value && !counted.has(el)) { counted.add(el); push("step", `field:${el.id}`); }
  });
  window.addEventListener("pagehide", flush);

  return {
    start(name, how) { flush(); flow = name; method = how; t0 = performance.now(); push("flow_start"); },
    setMethod(how) { method = how; },
    step(detail) { push("step", detail); },
    error(detail) { push("error", detail); },
    end(detail = "") { push("flow_end", detail); flush(); flow = null; },
    runId,
  };
})();
