"""Live alert dashboard: a tiny FastAPI app streaming IDS alerts over server-sent events.

The engine runs on its own thread; `Broadcaster.push` is safe to call from any thread and hands each
alert to every connected SSE client's asyncio queue via `loop.call_soon_threadsafe`.
Requires the `web` extra (fastapi, uvicorn).
"""

from __future__ import annotations

import asyncio
import json
import threading
from collections import deque
from typing import Optional

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, StreamingResponse

from ids.core import Alert, AttackClass

KEEPALIVE_S = 15.0


class Broadcaster:
    """Thread-safe fan-out of alert dicts to asyncio subscribers, with a bounded replay history."""

    def __init__(self, history: int = 500):
        self._lock = threading.Lock()
        self._history: deque[dict] = deque(maxlen=history)
        self._subs: list[tuple[asyncio.AbstractEventLoop, asyncio.Queue]] = []

    @property
    def n_subscribers(self) -> int:
        with self._lock:
            return len(self._subs)

    def snapshot(self) -> list[dict]:
        with self._lock:
            return list(self._history)

    def push(self, alert: Alert) -> None:
        """Engine-side entry point (usable directly as `on_alert`); callable from any thread."""
        d = alert.to_dict()
        with self._lock:
            self._history.append(d)
            subs = list(self._subs)
        for loop, q in subs:
            try:
                loop.call_soon_threadsafe(q.put_nowait, d)
            except RuntimeError:  # that client's event loop has closed
                self._drop(q)

    def subscribe(self) -> tuple[asyncio.Queue, list[dict]]:
        """Call from the asyncio side. Returns (queue of future alerts, history to replay first)."""
        q: asyncio.Queue = asyncio.Queue()
        loop = asyncio.get_running_loop()
        with self._lock:  # atomic w.r.t. push: every alert is either in the replay or in the queue
            replay = list(self._history)
            self._subs.append((loop, q))
        return q, replay

    def _drop(self, q: asyncio.Queue) -> None:
        with self._lock:
            self._subs = [s for s in self._subs if s[1] is not q]

    unsubscribe = _drop


def create_app(broadcaster: Broadcaster, max_events: Optional[int] = None) -> FastAPI:
    """Build the dashboard app. `max_events` ends each /events stream after that many alerts
    (test mode; None streams forever)."""
    app = FastAPI(title="Drone IDS dashboard")

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return PAGE.replace("__CLASSES__", json.dumps([c.value for c in AttackClass]))

    @app.get("/events")
    async def events() -> StreamingResponse:
        q, replay = broadcaster.subscribe()

        async def stream():
            sent = 0
            try:
                if max_events is not None and max_events <= 0:
                    return
                pending = list(replay)
                while True:
                    if pending:
                        d = pending.pop(0)
                    else:
                        try:
                            d = await asyncio.wait_for(q.get(), KEEPALIVE_S)
                        except asyncio.TimeoutError:
                            yield ": keepalive\n\n"
                            continue
                    yield f"data: {json.dumps(d)}\n\n"
                    sent += 1
                    if max_events is not None and sent >= max_events:
                        return
            finally:
                broadcaster.unsubscribe(q)

        return StreamingResponse(stream(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    return app


def start_dashboard(broadcaster: Broadcaster, port: int, host: str = "127.0.0.1") -> threading.Thread:
    """Serve the dashboard from a daemon thread (loopback by default) and return that thread."""
    import uvicorn

    server = uvicorn.Server(uvicorn.Config(create_app(broadcaster), host=host, port=port, log_level="warning"))
    t = threading.Thread(target=server.run, name="ids-dashboard", daemon=True)
    t.start()
    return t


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Drone IDS - live alerts</title>
<style>
:root { color-scheme: light dark; --bg:#f6f7f9; --fg:#1b1f24; --card:#fff; --line:#d7dbe0; --mute:#5b6570;
        --low:#2e7d32; --medium:#b26a00; --high:#c62828; --critical:#8e0038; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#0f1317; --fg:#e6e9ed; --card:#181e25; --line:#2b333c; --mute:#93a0ad;
          --low:#66bb6a; --medium:#ffb74d; --high:#ef5350; --critical:#f06292; } }
* { box-sizing: border-box; }
body { margin:0; padding:16px; background:var(--bg); color:var(--fg);
       font:14px/1.4 system-ui, -apple-system, "Segoe UI", sans-serif; }
header { display:flex; align-items:baseline; gap:12px; flex-wrap:wrap; margin-bottom:12px; }
h1 { font-size:18px; margin:0; }
#status { color:var(--mute); font-size:12px; }
#counters { display:grid; grid-template-columns:repeat(auto-fill,minmax(150px,1fr)); gap:8px; margin-bottom:16px; }
.ctr { background:var(--card); border:1px solid var(--line); border-radius:6px; padding:8px 10px; }
.ctr b { display:block; font-size:22px; font-variant-numeric:tabular-nums; }
.ctr span { color:var(--mute); font-size:12px; }
.ctr.hit b { color:var(--high); }
.wrap { overflow-x:auto; background:var(--card); border:1px solid var(--line); border-radius:6px; }
table { border-collapse:collapse; width:100%; }
th, td { text-align:left; padding:6px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
th { color:var(--mute); font-weight:600; font-size:12px; position:sticky; top:0; background:var(--card); }
td.num { font-variant-numeric:tabular-nums; white-space:nowrap; }
.sev { font-weight:700; text-transform:uppercase; font-size:12px; }
.sev.low { color:var(--low); } .sev.medium { color:var(--medium); }
.sev.high { color:var(--high); } .sev.critical { color:var(--critical); }
#empty { color:var(--mute); padding:12px 10px; }
</style></head>
<body>
<header><h1>Drone IDS - live alerts</h1><span id="status">connecting...</span></header>
<div id="counters"></div>
<div class="wrap"><table>
<thead><tr><th>Time</th><th>Severity</th><th>Class</th><th>Score</th><th>Reasons</th><th>Detectors</th></tr></thead>
<tbody id="rows"></tbody></table>
<div id="empty">No alerts yet.</div></div>
<script>
const CLASSES = __CLASSES__;
const counts = {}, ctrEls = {};
const ctrBox = document.getElementById("counters");
for (const c of CLASSES) {
  counts[c] = 0;
  const d = document.createElement("div"); d.className = "ctr";
  const n = document.createElement("b"); n.textContent = "0";
  const l = document.createElement("span"); l.textContent = c;
  d.append(n, l); ctrBox.append(d); ctrEls[c] = [d, n];
}
const rows = document.getElementById("rows"), empty = document.getElementById("empty");
const status = document.getElementById("status");
const MAX_ROWS = 500;
function cell(text, cls) { const td = document.createElement("td"); td.textContent = text; if (cls) td.className = cls; return td; }
function add(a) {  // textContent only: alert reasons can contain attacker-controlled strings
  empty.style.display = "none";
  counts[a.attack_class] = (counts[a.attack_class] || 0) + 1;
  if (ctrEls[a.attack_class]) {
    ctrEls[a.attack_class][1].textContent = counts[a.attack_class];
    ctrEls[a.attack_class][0].classList.add("hit");
  }
  const tr = document.createElement("tr");
  const sev = cell(a.severity, "sev " + String(a.severity).replace(/[^a-z]/g, ""));
  tr.append(cell(Number(a.t_alert).toFixed(2), "num"), sev, cell(a.attack_class),
            cell(a.score, "num"), cell((a.reasons || []).join("; ")), cell((a.detectors || []).join(", ")));
  rows.prepend(tr);
  while (rows.children.length > MAX_ROWS) rows.lastChild.remove();
}
const es = new EventSource("/events");
es.onopen = () => { status.textContent = "live"; };
es.onerror = () => { status.textContent = "disconnected - retrying"; };
es.onmessage = (e) => add(JSON.parse(e.data));
</script>
</body></html>
"""
