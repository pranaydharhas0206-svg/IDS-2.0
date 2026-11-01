# Detector changes made while running the benchmark (for the proposal)

Method: calibrate on the first half of `sample_data/ardupilot_sample.tlog`, evaluate on the second half.
Every change below fixes a root cause in detector logic, a floor, or the calibration rule, and has a
regression test in `tests/test_ids_residual.py`. No threshold was tuned to the evaluation half.

First benchmark run (before changes): 19/20 detected, 1 false positive (att_ahrs2 burst), 1 miss
(telemetry `battery`, +2 V).

## Diagnosis

The 7 `att_ahrs2` + 1 `hud_heading` false findings (Task 3, held-out half) all sit at t = 2319-2324 s,
the end of the recorded flight, where the vehicle is at -0.8 m relative altitude, rolls 0 -> 180 deg at up to
125 deg/s and ends upside down (a genuine crash / flip). During the tumble the ATTITUDE and AHRS2 messages
(and VFR_HUD vs GLOBAL_POSITION_INT) are 0.3-0.66 s apart in arrival time, so two correct estimates
legitimately differ by rate x gap (about 40-60 deg). The checks compared them as if simultaneous.

The battery miss: `batt_jump` compared consecutive samples. (1) Load steps change terminal voltage by up to
2.8 V between samples (I x R sag), so the calibrated threshold became 2.208 V, above a +2 V tamper. (2) A
constant offset only creates two edge samples (on and off), a poor signal even at low thresholds.

## Changes

| # | File / check | Change | Root cause |
|---|---|---|---|
| 1 | `checks.py` `AttAhrs2` | Each roll/pitch difference is shrunk toward zero by `abs(rate) x abs(message-time gap)` (rate = ATTITUDE roll/pitch speed) before the 3 s windowed mean. | Sampling skew during fast manoeuvres was read as tampering. Calibrated threshold drops 11.79 -> 7.26 deg, so sensitivity improves. |
| 2 | `checks.py` `HudHeading` | Residual = `wrap(hud - gpi_hdg) - abs(yawspeed) x abs(message-time gap)`, floored at 0. | Same skew, on heading during a fast spin. Calibrated threshold drops 43.68 -> 17.51 deg. |
| 3 | `checks.py` `BattJump` replaced by `BattVolt` (`batt_volt`) | Residual = deviation of the load-compensated voltage `V + 0.055 ohm x I` from its running median over 10 s. R fitted by differential V/I regression on the calibration half (0.057; the held-out half gives 0.051, so the model transfers). | Consecutive-sample jump saw load sag as jumps (inflated threshold) and saw a constant offset only at its edges. Calibrated threshold 2.21 -> 1.48 V; the +2 V tamper is now caught. |
| 4 | Floors (`checks.py`) | `gps_baro_alt` 5 -> 10 m, `att_ahrs2` 5 -> 7 deg, `batt_volt` 0.5 -> 1.0 V. | With default (uncalibrated) thresholds the old floors sat below normal noise (GPS vertical error vs barometer, estimator disagreement, load sag), producing the 8 false alerts Task 6 saw on an unattacked slice. The new floors equal the values the calibration rule (2 x q99.9) yields on the calibration half, rounded, so the uncalibrated fallback is now benign on this flight. They are a fallback, not a substitute for calibrating per airframe. |

Calibration rule (`calibrate.py`) unchanged: `thr = max(floor, 2 x q99.9(benign residuals))`.

## Effect (default thresholds, unattacked flight, findings in first / second half)

- Before: gps_baro_alt 5/24, batt_jump 30/21, att_ahrs2 8/66, hud_heading 16/45, hud_alt 1/0, gps_vel_mismatch 0/1
- After changes 1-3 only: gps_baro_alt 5/24, batt_volt 27/1, att_ahrs2 0/6, hud_alt 1/0, gps_vel_mismatch 0/1
- After changes 1-4: see `results.md` (calibrated run: 0 false positives on the held-out half).

## Held-out residual maxima vs calibrated thresholds (after fixes)

| check | threshold (from first half) | held-out max |
|---|---|---|
| att_ahrs2 | 7.26 | 6.39 |
| hud_heading | 17.51 | 14.57 |
| batt_volt | 1.48 | 0.67 |
| gps_baro_alt | 10.03 | 8.08 |
| gps_vel_mismatch | 5.05 | 4.77 |

Margins are thin for att_ahrs2 and gps_vel_mismatch; one flight is not enough to claim they generalise.

## Limitations to state in the proposal

- One flight; only ~0.34 h held out (the last ~400 s airborne + ground time), so 0 false positives is a weak
  bound (95% upper bound about 9 / flight-hour).
- Airborne time in the held-out half only fits 3-4 non-overlapping (90 s gap) instances per class, not 5;
  20 instances at seed 7 (20-24 at other seeds, all detected; see report).
- Replay attacks trigger residual findings too, so mavlink_anomaly instances are also flagged as
  telemetry_manipulation/gps_spoofing (confusion table); DoS floods also flag mavlink_anomaly.
- Held-out flight ends in a genuine crash; the tumble is no longer flagged after fix 1-2 (arguably it
  is an event a user would want flagged, but not as a telemetry attack).
