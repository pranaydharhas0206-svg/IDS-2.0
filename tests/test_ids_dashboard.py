import json
import threading
import time

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient  # noqa: E402

from ids.cli import build_parser, main  # noqa: E402
from ids.core import Alert, AttackClass  # noqa: E402
from ids.dashboard import Broadcaster, create_app  # noqa: E402


def _alert(t=1.0, cls=AttackClass.DOS, reasons=("flood",)):
    return Alert(t_first=t - 0.5, t_alert=t, attack_class=cls, severity="high", score=0.9,
                 reasons=list(reasons), detectors=["rate"])


def _events(client, n):
    out = []
    with client.stream("GET", "/events") as r:
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/event-stream")
        for line in r.iter_lines():
            if line.startswith("data: "):
                out.append(json.loads(line[6:]))
    assert len(out) == n
    return out


def test_index_serves_html_with_every_class_counter():
    client = TestClient(create_app(Broadcaster(), max_events=0))
    r = client.get("/")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    assert "/events" in r.text
    for c in AttackClass:
        assert c.value in r.text


def test_alert_pushed_before_connect_is_replayed_on_events():
    bc = Broadcaster()
    bc.push(_alert(1.0))
    got = _events(TestClient(create_app(bc, max_events=1)), 1)
    assert got[0] == _alert(1.0).to_dict()


def test_alert_pushed_from_another_thread_reaches_open_stream():
    bc = Broadcaster()

    def producer():
        deadline = time.time() + 5
        while bc.n_subscribers == 0 and time.time() < deadline:
            time.sleep(0.01)
        bc.push(_alert(2.0, AttackClass.GPS_SPOOFING))
        bc.push(_alert(3.0, AttackClass.COMMAND_INJECTION))

    t = threading.Thread(target=producer, daemon=True)
    t.start()
    got = _events(TestClient(create_app(bc, max_events=2)), 2)
    t.join(5)
    assert [g["attack_class"] for g in got] == ["gps_spoofing", "command_injection"]
    assert bc.n_subscribers == 0  # unsubscribed once the stream ended


def test_history_is_bounded():
    bc = Broadcaster(history=3)
    for i in range(10):
        bc.push(_alert(float(i)))
    assert [a["t_alert"] for a in bc.snapshot()] == [7.0, 8.0, 9.0]


def test_live_parser_accepts_dashboard_port():
    a = build_parser().parse_args(["live", "--dashboard", "8765"])
    assert a.dashboard == 8765
    assert build_parser().parse_args(["live"]).dashboard is None


def test_live_wires_dashboard_alongside_console_print(monkeypatch, capsys):
    import ids.dashboard as dash
    import ids.live as live

    started = {}
    monkeypatch.setattr(dash, "start_dashboard", lambda bc, port, host="127.0.0.1": started.update(bc=bc, port=port))

    def fake_router(master, gcs, eng):
        eng.on_alert(_alert(5.0))

    monkeypatch.setattr(live, "run_router", fake_router)
    assert main(["live", "--dashboard", "8765"]) == 0
    assert started["port"] == 8765
    assert [a["t_alert"] for a in started["bc"].snapshot()] == [5.0]
    assert "dos" in capsys.readouterr().out  # _print_alert still active
