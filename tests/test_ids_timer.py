from ids.core import AttackClass
from ids.engine import build_engine
from tests.ids_helpers import Stream, hb


def test_engine_emits_dos_alert_when_vehicle_heartbeat_stops():
    stream = Stream()
    alerts = []
    engine = build_engine(on_alert=alerts.append)
    engine.process(hb(stream, 100.0, armed=True))
    # No further messages arrive. The live loop's timer still evaluates link loss.
    engine.tick(106.0)
    engine.tick(107.1)
    assert any(a.attack_class == AttackClass.DOS for a in alerts)
