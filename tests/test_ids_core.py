import itertools
from pathlib import Path

from ids.core import Alert, AttackClass, Msg
from ids.sources import iter_tlog
from ids.state import VehicleState
from tests.ids_helpers import Stream, gcs_hb, gpi, hb

TLOG = Path(__file__).resolve().parents[1] / "sample_data" / "ardupilot_sample.tlog"


def test_iter_tlog_yields_normalized_msgs():
    msgs = list(itertools.islice(iter_tlog(TLOG), 2000))
    assert len(msgs) == 2000
    assert all(isinstance(m, Msg) for m in msgs)
    assert "mavpackettype" not in msgs[0].fields
    assert {m.src for m in msgs} >= {(1, 1)}
    assert msgs[0].t > 1e9  # unix timestamps from the tlog


def test_vehicle_state_tracks_vehicle_not_gcs():
    s, st = Stream(), VehicleState()
    st.update(gcs_hb(s, 0.0))
    assert st.vehicle_src is None
    st.update(hb(s, 0.1, armed=True))
    assert st.vehicle_src == (1, 1) and st.armed
    st.update(gpi(s, 0.2, rel_m=10.0))
    assert st.airborne
    st.update(hb(s, 1.0, armed=False))
    assert not st.airborne


def test_alert_to_dict_serialises_enum():
    a = Alert(1.0, 2.0, AttackClass.DOS, "high", 1.2, ["r"], ["protocol"])
    assert a.to_dict()["attack_class"] == "dos"
