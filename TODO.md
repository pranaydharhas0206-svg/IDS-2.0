# TODO: Drone IDS (Objective 2, branch `drone-ids`)

The single list of remaining work for the Drone IDS, in three stages. Other files describe what exists or what is
promised in the submission; they do not keep their own to-do lists. Objective 1 (forensics toolkit) work is tracked in
`docs/design_document.md` and is out of scope here. Last updated 2026-09-19.

Legend: `[ ]` open. Stage 2 items carry an ID (S2.n) so other documents can refer to them.

## Stage 1: submit by Sun 2026-09-20 23:59 IST

The official deadline is 27 Sept; the earlier date is our own choice. Engineering for Stage 1 is finished (205 tests
passing). On 2026-09-20 the whole-branch review was done and its cheap findings fixed (torn-log restart, non-ASCII HMAC
crash, manifest re-signing, unbounded timing list, radio-noise and trusted-GCS `PARAM_SET` false positives, sustained
heartbeat loss weight); the proposal budget was re-checked against retailer listings and rebalanced. What is left is
human work:

- [x] Final whole-branch review, then fix what it finds (2026-09-20; leftovers are S2.10, S2.15 and S2.16 below).
- [ ] Record the demo video following `docs/ids/demo_script.md` (every command re-run on 2026-09-20 and the quoted
      output matches). There is no SITL clip, so use the loopback live test.
- [x] Verify the budget table (proposal Section 12). Done against retailer search listings, which disagree widely; the
      battery and fixture lines have no quote. Do one final look at a real cart if time allows.
- [ ] Send the organisers the email in `docs/ids/organiser_email.md` (fill in their address and your name).
- [x] Source of truth for the proposal: **`proposal.md`**. `proposal.docx` and `proposal.pdf` are derived from it; after
      any edit, patch or regenerate both (PDF route in `state.md`).
- [ ] Submit `submission/aeroxperts_ids_stage1.zip` (built from the committed tree) plus the demo video.

## Stage 2: ₹1 lakh grant

### Validation and evidence

- [ ] **S2.1 SITL closed-loop runs.** Bring up ArduPilot SITL on a working Linux environment (the authoring machine's
      WSL distro disk is missing; `docs/ids/sitl_runbook.md` is written but untested). Run GPS glitch
      (`SIM_GPS1_GLTCH_*`), injection and flood scenarios through `ids live`. Replay-mode GPS spoofing is open-loop and
      optimistic, so no accuracy claim about live GPS spoofing until this is done.
- [ ] **S2.2 Wired, shielded GPS-spoof fixture** for closed-loop tests on the bench and in tethered flight. No
      over-the-air GNSS transmission, ever (illegal without authorisation).
- [ ] **S2.3 Hardware-in-the-loop rig.** Pixhawk 6C plus Raspberry Pi 5 on TELEM2, IDS inline between the flight
      controller and the SiK radio.
- [ ] **S2.4 Multi-flight calibration and a real false-positive bound.** Record several benign flights (different days,
      payloads, modes, manual and mission). Hold out whole flights, report FP per flight-hour with a confidence
      interval, and choose the threshold floors before looking at evaluation data (the current floors were chosen after
      seeing both halves of the one flight: mild leakage). Today's "0 FP" bounds the rate only to about 9 per hour at
      95 % confidence.
- [ ] **S2.5 Cross-validate on public UAV attack datasets.**
- [ ] **S2.6 Measure real Raspberry Pi 5 timing and latency on the UART.** The Pi figures in the proposal are estimates.
- [ ] **S2.7 Field trials for "distance covered"**, once the organisers define it.
- [ ] **S2.8 Independently authored adversarial test set,** written by someone who has not read the detector code:
      slow drift below the residual thresholds, a spoofer that keeps a 3D fix and matches GPS speed, attacks that begin
      during warm-up, in-sequence forged sender IDs. All current attacks are ours, authored with the detectors in view.

### Hardening

Fixed already (2026-09-19, see `docs/ids/hardening.md`): fail-safe engine and router, vehicle-identity pinning and
claim detection, strict allowlist option, GPS-fix-loss evidence, critical-class fusion cooldown, log `fsync` and signed
anchor, signed firmware manifest, startup notices. What remains, in priority order:

- [ ] **S2.9 MAVLink 2 message signing.** The real fix for forged sender IDs: an in-sequence forged-GCS disarm is
      currently invisible. Provision a shared secret on the flight controller and GCS; treat any unsigned or
      bad-signature frame on a signed link as command injection. Removes most identity heuristics. No extra hardware.
- [ ] **S2.10 Independent IDS watchdog and off-vehicle evidence.** A separate microcontroller board expects a heartbeat
      from the IDS and raises an alert or fails over to pass-through if it stalls (the in-process fault handling cannot
      help if the process is killed, starved by a flood, or loses power). Stream alerts and log anchors off the vehicle
      (syslog or MQTT over the telemetry link). Switch alert and manifest signing from HMAC to Ed25519 so the verifier
      holds no secret an attacker on the vehicle could steal.
- [ ] **S2.11 Decouple analysis from forwarding.** The router is single-threaded, so a very high message rate delays
      forwarding as well as detection. Use a bounded queue and a worker thread with a drop counter; measure on the real
      UART (S2.6).
- [ ] **S2.12 Broader policy and telemetry checks.** `dangerous_command` covers disarm, flight termination, reboot and
      `PARAM_SET` from non-vehicle sources while airborne; add mode changes, mission uploads, RC override and geofence
      edits as low-weight evidence with per-deployment allow rules. Add per-message-type freshness checks against a
      man-in-the-middle that drops telemetry while heartbeats continue. Replace the single vehicle identity with a
      per-vehicle state map so a legitimate second autopilot (swarm, redundant FC) is not flagged as an identity claim
      (workaround today: `--trusted`).
- [ ] **S2.13 Runtime firmware attestation and dashboard authentication.** The IDS only sees a firmware change if it
      runs at boot (banner) or a parameter is downloaded; add a measured-boot digest reported by the flight controller.
      The dashboard is unauthenticated and loopback-only; add authentication and rate-limited SSE clients.
- [ ] **S2.15 Authenticate the detector configuration.** The calibrated profile directory (`thresholds.json`,
      `baseline.json`, and the pickle-based `ml.joblib`) is loaded without any signature, so write access to it lets an
      attacker blind the IDS or, through the pickle, run code at startup. Sign the profile with the alert key, verify at
      load, and drop pickle for a safe model format. Until then keep the profile directory read-only and root-owned.
- [ ] **S2.16 Timer-driven link-loss checks.** Heartbeat loss is evaluated only when the next vehicle heartbeat
      arrives, so a jam that never ends raises nothing. Add a tick in the live router (and off-vehicle, S2.10).
      Malformed-frame evidence is capped at 0.5 per window so noise cannot alert; a pure garbage flood is therefore
      caught only through the rate and source checks, revisit with real link data (S2.4).
- [ ] **S2.14 IPS (blocking) mode, last.** Only after S2.4 gives a trustworthy FP rate: block only critical,
      high-confidence classes, behind an operator switch and a hardware bypass so the link survives an IDS failure.

## Beyond Stage 2

- [ ] ArduPilot secure-boot attestation across airframes: move firmware integrity from "what the vehicle claims" to a
      signed measurement, fleet-wide.
- [ ] C/Rust port of the hot path for microcontroller-class deployment (Python stays the reference and test oracle).
- [ ] A public benchmark protocol across airframes and firmware.
- [ ] "Distance covered" long-range trials, once defined (continues S2.7).
- [ ] Fleet features: alert aggregation to a ground service, and the Objective 1 forensic hand-off.

## Honest bound on the claims (keep in any submission text)

The IDS is fail-safe (it degrades loudly, not silently), its logs are tamper-evident when anchored, and the cheap
evasions found in review are closed. It is still a detector calibrated on one real flight with authored attacks, and it
cannot authenticate a sender without MAVLink 2 signing.
