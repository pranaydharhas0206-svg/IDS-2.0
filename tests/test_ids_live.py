import threading
import time

from pymavlink import mavutil

from ids.engine import build_engine
from ids.live import run_router, send_attack


def test_router_forwards_and_detects_rogue_command():
    alerts = []
    eng = build_engine(on_alert=alerts.append)
    eng.detectors[0].warmup_s = 1.0  # protocol detector: short warmup for the test
    stop = threading.Event()
    th = threading.Thread(target=run_router, args=("udpin:127.0.0.1:14650", "udpin:127.0.0.1:14651", eng, stop), daemon=True)
    th.start()
    vehicle = mavutil.mavlink_connection("udpout:127.0.0.1:14650", source_system=1, source_component=1)
    for _ in range(15):
        vehicle.mav.heartbeat_send(2, 3, 129, 0, 4)
        time.sleep(0.1)
    send_attack("udpout:127.0.0.1:14651", "inject", duration=0.5)
    time.sleep(0.5)
    stop.set()
    th.join(timeout=2)
    assert any(a.attack_class.value == "command_injection" for a in alerts)
