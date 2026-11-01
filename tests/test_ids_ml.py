import random

from ids.core import AttackClass
from ids.detectors.ml import FEATURES, MLDetector, WindowFeaturizer, train_ml
from ids.state import VehicleState
from tests.ids_helpers import Stream, gcs_hb, gpi, hb


def traffic(s, t0, seconds, extra_rate=0):
    # seeded jitter: ~10% dropped telemetry so benign windows vary (an IsolationForest cannot split identical rows)
    rng = random.Random(int(t0))
    out = []
    for i in range(int(seconds * 10)):
        t = t0 + i * 0.1
        if i % 10 and rng.random() < 0.1:
            continue
        out.append(hb(s, t) if i % 10 == 0 else gpi(s, t, rel_m=20.0))
        if i % 10 == 0:
            out.append(gcs_hb(s, t))
        for k in range(extra_rate // 10):
            out.append(s(t + k * 0.001, "PARAM_REQUEST_LIST", src=(255, 0), target_system=1, target_component=1))
    return out


def test_featurizer_emits_one_vector_per_window():
    s, st = Stream(), VehicleState()
    fz = WindowFeaturizer(st)
    vecs = []
    for m in traffic(s, 0.0, 5):
        st.update(m)
        v = fz.feed(m)
        if v is not None:
            vecs.append(v)
    assert len(vecs) == 4 and all(len(v) == len(FEATURES) for v in vecs)


def test_ml_flags_flood_but_not_benign():
    s = Stream()
    model = train_ml(traffic(s, 0.0, 300))
    st = VehicleState()
    det = MLDetector(st, model)
    benign_hits, attack_hits = [], []
    for m in traffic(s, 300.0, 60):
        st.update(m)
        benign_hits += det.feed(m)
    for m in traffic(s, 360.0, 10, extra_rate=400):
        st.update(m)
        attack_hits += det.feed(m)
    assert len(benign_hits) <= 1
    assert attack_hits and attack_hits[0].attack_class == AttackClass.ANOMALY
