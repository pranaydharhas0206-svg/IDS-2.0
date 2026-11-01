import pytest

from ids.attacks import ATTACKS, make_attack
from ids.core import AttackClass
from ids.engine import build_engine
from ids.sources import iter_tlog
from ids.state import VehicleState
from tests.test_ids_core import TLOG


@pytest.fixture(scope="module")
def log():
    msgs = []
    for m in iter_tlog(TLOG):
        msgs.append(m)
        if m.t - msgs[0].t > 720:
            break
    return msgs


@pytest.fixture(scope="module")
def airborne_t(log):
    st, out = VehicleState(), []
    for m in log:
        st.update(m)
        if st.airborne and m.type == "GLOBAL_POSITION_INT":
            out.append(m.t)
    assert out, "sample log must contain airborne time in its first 12 minutes"
    return out


def test_every_attack_labels_its_messages_and_preserves_originals(log, airborne_t):
    start = airborne_t[len(airborne_t) // 2]
    for cls in ATTACKS:
        atk = make_attack(cls, start, 0, seed=1)
        out = atk.apply(log)
        labelled = [m for m in out if m.label == cls]
        assert labelled, cls
        assert all(start - 1 <= m.t <= atk.end + 1 for m in labelled), cls
        assert sum(1 for m in out if m.label is None) >= len(log) - len(labelled)


@pytest.mark.parametrize("cls", list(ATTACKS))
def test_engine_detects_each_attack_class(log, airborne_t, cls):
    start = airborne_t[len(airborne_t) // 2]
    for index in range(len(ATTACKS[cls].VARIANTS)):
        atk = make_attack(cls, start, index, seed=3)
        alerts = build_engine(baseline=_baseline(log)).run(atk.apply(log))
        hits = [a for a in alerts if a.attack_class == cls and start <= a.t_alert <= atk.end + 10]
        assert hits, f"{cls} variant {atk.variant} not detected"


def _baseline(log):
    from ids.detectors.integrity import build_baseline
    return build_baseline(log)
