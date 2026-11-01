from ids.core import AttackClass
from ids.detectors.protocol import ProtocolDetector
from ids.state import VehicleState
from tests.ids_helpers import Stream, gcs_hb, gpi, hb


def setup(warmup=10.0):
    s, st = Stream(), VehicleState()
    det = ProtocolDetector(st, warmup_s=warmup)

    def feed(m):
        st.update(m)
        return det.feed(m)

    # warmup traffic: vehicle 10 Hz, GCS 1 Hz
    for i in range(100):
        t = i * 0.1
        feed(hb(s, t) if i % 10 == 0 else gpi(s, t, rel_m=20.0))
        if i % 10 == 0:
            feed(gcs_hb(s, t))
    return s, st, feed


def classes(findings):
    return [f.attack_class for f in findings]


def test_command_from_unknown_source_is_injection():
    s, _, feed = setup()
    out = feed(s(11.0, "COMMAND_LONG", src=(66, 1), command=400, param1=0, param2=21196))
    assert AttackClass.COMMAND_INJECTION in classes(out)
    assert max(f.score for f in out if f.attack_class == AttackClass.COMMAND_INJECTION) == 1.0


def test_backwards_sequence_is_anomaly_but_radio_duplicate_is_not():
    s, _, feed = setup()
    feed(s(11.0, "RADIO", src=(51, 68), seq=5))
    assert feed(s(11.0, "RADIO_STATUS", src=(51, 68), seq=5)) == []  # same seq, different type: benign
    out = feed(s(11.1, "GLOBAL_POSITION_INT", seq=3, lat=0, lon=0, alt=0, relative_alt=20000, vx=0, vy=0, vz=0, hdg=0))
    assert AttackClass.MAVLINK_ANOMALY in classes(out)


def test_disarm_in_flight_from_spoofed_gcs_with_seq_anomaly_scores_full():
    s, _, feed = setup()
    feed(s(11.0, "HEARTBEAT", src=(255, 0), seq=200, type=6, autopilot=8, base_mode=0, custom_mode=0, system_status=0))
    out = feed(s(11.2, "COMMAND_LONG", src=(255, 0), seq=17, command=400, param1=0, param2=21196))
    inj = [f for f in out if f.attack_class == AttackClass.COMMAND_INJECTION]
    assert inj and inj[0].score == 1.0


def test_disarm_in_flight_from_trusted_gcs_is_only_partial_evidence():
    s, _, feed = setup()
    out = feed(s(11.0, "COMMAND_LONG", src=(255, 0), command=400, param1=0, param2=0))
    inj = [f for f in out if f.attack_class == AttackClass.COMMAND_INJECTION]
    assert inj and inj[0].score < 1.0


def test_flood_is_dos():
    s, _, feed = setup()
    found = []
    for i in range(400):
        found += feed(s(11.0 + i * 0.002, "PARAM_REQUEST_LIST", src=(255, 0), target_system=1, target_component=1))
    assert AttackClass.DOS in classes(found)


def test_normal_traffic_after_warmup_is_silent():
    s, _, feed = setup()
    found = []
    for i in range(100, 300):
        t = i * 0.1
        found += feed(hb(s, t) if i % 10 == 0 else gpi(s, t, rel_m=20.0))
        if i % 10 == 0:
            found += feed(gcs_hb(s, t))
    assert found == []


def test_timer_tick_detects_heartbeat_loss_without_a_following_frame():
    # No later MAVLink frame is delivered, so only the timer path can
    # observe the outage.
    s = Stream()
    st = VehicleState()
    det = ProtocolDetector(st, warmup_s=0.0, hb_gap_s=2.0)
    vehicle_hb = s(100.0, "HEARTBEAT", src=(1, 1), type=2, autopilot=3,
                   base_mode=128, custom_mode=0, system_status=4)
    st.update(vehicle_hb)
    det.feed(vehicle_hb)
    out = det.tick(103.0)
    assert any(f.attack_class == AttackClass.DOS for f in out)
    assert det.tick(103.5) == []
    assert det.tick(104.1)  # periodic reminder while outage persists
