from ids.calibrate import calibrate
from ids.core import AttackClass
from ids.detectors.checks import default_checks, dist_m
from ids.detectors.residual import ResidualDetector
from ids.state import VehicleState
from tests.ids_helpers import Stream, gpi, gps, hb


def run(msgs, thresholds=None):
    st = VehicleState()
    det = ResidualDetector(st, default_checks(), thresholds or {})
    out = []
    for m in msgs:
        st.update(m)
        out += det.feed(m)
    return out


def benign(s, t0, n, lat0=-35.0):
    msgs = [hb(s, t0)]
    for i in range(n):
        t = t0 + i * 0.4
        lat = lat0 + i * 1e-6  # ~0.28 m/s north
        msgs.append(gpi(s, t, lat=lat, rel_m=20.0, vx=28))
        msgs.append(gps(s, t + 0.01, lat=lat, vel_cms=28))
    return msgs


def test_dist_m_one_millidegree_latitude():
    assert abs(dist_m(0.0, 0.0, 0.001, 0.0) - 111.3) < 0.5


def test_benign_gps_is_silent():
    assert run(benign(Stream(), 0.0, 100)) == []


def test_gps_jump_is_spoofing():
    s = Stream()
    msgs = benign(s, 0.0, 20)
    msgs.append(gpi(s, 8.0, lat=-35.0 + 20e-6, rel_m=20.0))
    msgs.append(gps(s, 8.01, lat=-35.0 + 20e-6 + 0.002, vel_cms=28))  # +222 m
    out = run(msgs)
    assert out and all(f.attack_class == AttackClass.GPS_SPOOFING for f in out)
    assert max(f.score for f in out) == 1.0


def test_hud_altitude_tamper_is_telemetry_manipulation():
    s = Stream()
    msgs = [hb(s, 0.0)]
    for i in range(80):
        t = i * 0.5
        msgs.append(gpi(s, t, rel_m=20.0))
        msgs.append(s(t + 0.01, "VFR_HUD", alt=20.0 + (30.0 if i >= 70 else 0.0), groundspeed=0.0,
                      airspeed=0.0, heading=0, throttle=40, climb=0.0))
    out = run(msgs)
    assert out and {f.attack_class for f in out} == {AttackClass.TELEMETRY_MANIPULATION}


def test_calibrate_returns_threshold_at_least_floor_for_every_check():
    thr = calibrate(benign(Stream(), 0.0, 200))
    floors = {c.name: c.floor for c in default_checks()}
    assert set(thr) == set(floors)
    assert all(thr[k] >= floors[k] for k in floors)


def test_attitude_offset_vs_ahrs2_is_telemetry_manipulation_but_jitter_is_not():
    def att(s, tampered):
        msgs = [hb(s, 0.0)]
        for i in range(40):
            t = i * 0.3
            jitter = 0.01 if i % 2 else -0.01  # zero-mean estimator disagreement
            msgs.append(s(t, "AHRS2", roll=0.0, pitch=0.0, yaw=0.0, altitude=0.0, lat=0, lng=0))
            msgs.append(s(t + 0.01, "ATTITUDE", roll=jitter + (0.5 if tampered and i >= 20 else 0.0), pitch=0.0,
                          yaw=0.0, rollspeed=0.0, pitchspeed=0.0, yawspeed=0.0, time_boot_ms=0))
        return msgs

    assert run(att(Stream(), False)) == []
    out = run(att(Stream(), True))
    assert out and {f.attack_class for f in out} == {AttackClass.TELEMETRY_MANIPULATION}


# ---- regressions found while root-causing benchmark false positives / misses (Task 7) ----

def _att_stream(s, roll_deg, rate_dps, ahrs2_age, n=30, tampered=False):
    """ATTITUDE rolling at rate_dps; AHRS2 is a genuine, correct estimate sampled `ahrs2_age` s earlier."""
    import math
    msgs = [hb(s, 0.0)]
    for i in range(n):
        t = i * 0.3
        r = math.radians(roll_deg + rate_dps * t)
        r_old = math.radians(roll_deg + rate_dps * (t - ahrs2_age))
        msgs.append(s(t - ahrs2_age + 0.0001, "AHRS2", roll=r_old, pitch=0.0, yaw=0.0, altitude=0.0, lat=0, lng=0))
        msgs.append(s(t, "ATTITUDE", roll=r + (0.35 if tampered else 0.0), pitch=0.0, yaw=0.0,
                      rollspeed=math.radians(rate_dps), pitchspeed=0.0, yawspeed=0.0, time_boot_ms=0))
    return msgs


def test_att_ahrs2_fast_tumble_with_message_skew_is_not_tampering():
    # 120 deg/s flip, AHRS2 0.5 s stale -> raw difference ~60 deg, entirely explained by sampling skew
    assert run(_att_stream(Stream(), 0.0, 120.0, 0.5)) == []
    # an offset on top of a slow, skewed manoeuvre is still caught
    assert run(_att_stream(Stream(), 0.0, 10.0, 0.4, tampered=True))


def _hud_stream(s, hdg_offset, yaw_dps, gpi_age):
    import math
    msgs = [hb(s, 0.0)]
    for i in range(30):
        t = i * 0.3
        true_hdg = (100.0 + yaw_dps * t) % 360.0
        stale_hdg = (100.0 + yaw_dps * (t - gpi_age)) % 360.0
        g = gpi(s, t - gpi_age + 0.0001, rel_m=20.0, hdg=int(stale_hdg * 100))
        msgs.append(g)
        msgs.append(s(t - 0.001, "ATTITUDE", roll=0.0, pitch=0.0, yaw=0.0, rollspeed=0.0, pitchspeed=0.0,
                      yawspeed=math.radians(yaw_dps), time_boot_ms=0))
        msgs.append(s(t, "VFR_HUD", alt=20.0, groundspeed=0.0, airspeed=0.0, heading=int((true_hdg + hdg_offset) % 360),
                      throttle=40, climb=0.0))
    return msgs


def test_hud_heading_fast_spin_with_message_skew_is_not_tampering():
    assert run(_hud_stream(Stream(), 0.0, 90.0, 0.5)) == []          # 45 deg of skew from a 90 deg/s spin
    out = run(_hud_stream(Stream(), 60.0, 5.0, 0.3))                  # a real 60 deg heading lie
    assert out and {f.attack_class for f in out} == {AttackClass.TELEMETRY_MANIPULATION}


def _batt_stream(s, offset_v=0.0, tamper_from=60):
    msgs = [hb(s, 0.0)]
    for i in range(120):
        t = i * 0.5
        amps = 2.0 if (i // 10) % 2 == 0 else 30.0          # load steps every 5 s
        volt = 11.5 - 0.055 * amps + (offset_v if i >= tamper_from else 0.0)  # sag follows the load
        msgs.append(s(t, "SYS_STATUS", voltage_battery=int(volt * 1000), current_battery=int(amps * 100),
                      battery_remaining=80))
    return msgs


def test_batt_load_sag_steps_are_benign_but_constant_offset_is_caught():
    assert run(_batt_stream(Stream())) == []                        # 1.5 V load-induced steps: not tampering
    out = run(_batt_stream(Stream(), offset_v=2.0))                 # +2 V spoofed pack voltage
    assert out and {f.attack_class for f in out} == {AttackClass.TELEMETRY_MANIPULATION}


def test_gps_baro_alt_default_floor_tolerates_gps_vertical_noise():
    s = Stream()
    msgs = [hb(s, 0.0)]
    for i in range(80):
        t = i * 0.5
        gps_alt = 600.0 + (4.0 if (i // 10) % 2 else -4.0)          # 8 m GPS vertical steps, baro constant
        msgs.append(s(t, "SCALED_PRESSURE", press_abs=1000.0, press_diff=0.0, temperature=2000))
        msgs.append(gps(s, t + 0.01, alt_m=gps_alt))
    assert run(msgs) == []
