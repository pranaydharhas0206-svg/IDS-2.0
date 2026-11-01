"""Command-line interface: python -m ids <command> (or the `ids` console script)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ids.alertlog import AlertLog, load_key, verify_log
from ids.attacks import make_attack
from ids.core import Alert, AttackClass
from ids.sources import iter_tlog, load_tlog


def _print_alert(a: Alert) -> None:
    print(f"[{a.severity.upper():8}] t={a.t_alert:.2f} {a.attack_class.value:24} score={a.score:<5} "
          f"{'; '.join(a.reasons[:2])}", flush=True)


def parse_src(text: str) -> tuple[int, int]:
    """'SYS:COMP' -> (sysid, compid), for --vehicle / --trusted."""
    try:
        sysid, comp = (int(x) for x in text.split(":"))
        if not (0 <= sysid <= 255 and 0 <= comp <= 255):
            raise ValueError
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected SYS:COMP with values 0-255, got {text!r}") from None
    return sysid, comp


def startup_notices(thr, base, model) -> list[str]:
    """Tell the operator which detection layers are degraded, instead of running silently without them."""
    out = []
    if base is None:
        out.append("NOTICE: no integrity baseline loaded - firmware/parameter integrity checks are DISABLED "
                   "(create one with `ids calibrate`)")
    if thr is None:
        out.append("NOTICE: no calibrated thresholds - residual checks use their conservative floors "
                   "(run `ids calibrate` on benign flights)")
    return out


def _engine_from_args(a, thr, base, model, log, on_alert):
    from ids.engine import build_engine
    if a.no_learn_sources and not (a.trusted or a.vehicle):
        raise ValueError("--no-learn-sources needs --vehicle and/or --trusted (otherwise every source is unknown)")
    return build_engine(thresholds=thr, baseline=base, ml_model=model, log=log, on_alert=on_alert,
                        trusted=a.trusted or (), vehicle=a.vehicle, learn_sources=not a.no_learn_sources)


def _open_log(a):
    """Returns (log, error_code). --require-key fails fast, before any traffic is handled."""
    try:
        key = load_key(require=a.require_key)
    except RuntimeError as e:
        print(e)
        return None, 2
    if a.anchor and not a.log_out:
        print("--anchor needs --log")
        return None, 2
    return (AlertLog(a.log_out, key, anchor_path=a.anchor) if a.log_out else None), 0


def _add_identity_opts(p) -> None:
    p.add_argument("--vehicle", type=parse_src, metavar="SYS:COMP", help="pin the vehicle identity (e.g. 1:1)")
    p.add_argument("--trusted", type=parse_src, action="append", metavar="SYS:COMP",
                   help="always-allowed source; repeatable (e.g. the GCS 255:0)")
    p.add_argument("--no-learn-sources", action="store_true",
                   help="do not allowlist sources seen during warm-up; trust only --vehicle/--trusted")
    p.add_argument("--require-key", action="store_true", help="refuse to run without IDS_ALERT_KEY (no dev key)")
    p.add_argument("--anchor", metavar="FILE", help="write a signed log-head anchor here (store it off the log's disk)")


def load_profile(d: str | None):
    if not d:
        return None, None, None
    from ids.profile import verify_profile
    p = Path(d)
    ok, reason = verify_profile(p)
    if not ok:
        raise ValueError(f"refusing to load untrusted IDS profile: {reason}; run `ids calibrate` again")
    thr = json.loads((p / "thresholds.json").read_text()) if (p / "thresholds.json").exists() else None
    base = json.loads((p / "baseline.json").read_text()) if (p / "baseline.json").exists() else None
    model = None
    if (p / "ml.joblib").exists():
        import joblib
        model = joblib.load(p / "ml.joblib")  # only after profile signature and file digest verify
    return thr, base, model


def cmd_calibrate(a) -> int:
    from ids.calibrate import calibrate
    from ids.detectors.integrity import build_baseline
    msgs = load_tlog(a.log)
    cut = msgs[0].t + a.frac * (msgs[-1].t - msgs[0].t)
    benign = [m for m in msgs if m.t < cut]
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "thresholds.json").write_text(json.dumps(calibrate(benign), indent=2))
    (out / "baseline.json").write_text(json.dumps(build_baseline(benign), indent=2))
    if a.ml:
        import joblib
        from ids.detectors.ml import train_ml
        joblib.dump(train_ml(benign), out / "ml.joblib")
    from ids.profile import sign_profile
    sign_profile(out)
    print(f"signed profile written to {out} from {len(benign)} benign messages")
    return 0


def _parse_attack(spec: str, t0: float):
    name, _, rest = spec.partition("@")
    offset, _, idx = rest.partition(":")
    return make_attack(AttackClass(name), t0 + float(offset), int(idx or 0), seed=0)


def cmd_replay(a) -> int:
    try:
        thr, base, model = load_profile(a.profile)
    except (ValueError, OSError) as e:
        print(e)
        return 2
    log, rc = _open_log(a)
    if rc:
        return rc
    for n in startup_notices(thr, base, model):
        print(n)
    msgs = []
    for m in iter_tlog(a.log):
        if msgs and a.max_seconds and m.t - msgs[0].t > a.max_seconds:
            break
        msgs.append(m)
    for spec in a.attack or []:
        msgs = _parse_attack(spec, msgs[0].t).apply(msgs)
    try:
        eng = _engine_from_args(a, thr, base, model, log, _print_alert)
    except ValueError as e:
        print(e)
        return 2
    alerts = eng.run(msgs)
    print(f"{len(msgs)} messages, {eng.n_findings} findings, {len(alerts)} alerts")
    if eng.faults or eng.sink_errors:
        print(f"WARNING: IDS faults {dict(eng.faults)}, alert-sink errors {eng.sink_errors}")
    return 0


def cmd_bench(a) -> int:
    from ids.bench import run_bench, write_results
    res = run_bench(load_tlog(a.log), n_per_class=a.n, seed=a.seed, use_ml=a.ml)
    write_results(res, a.out)
    print((Path(a.out) / "results.md").read_text(encoding="utf-8"))
    return 0


def cmd_verify(a) -> int:
    try:
        text = Path(a.file).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        print(f"cannot read alert log {a.file}: {getattr(e, 'strerror', None) or e}")
        return 1
    if not text.strip():
        print("empty log - nothing to verify")
        return 1
    ok, idx, why = verify_log(a.file, load_key(), anchor=a.anchor)
    print("OK: alert log intact" if ok else f"TAMPERED at record {idx}: {why}" if idx is not None else f"TAMPERED: {why}")
    if ok and not a.anchor:
        print("note: no --anchor given, so deletion of the newest records cannot be ruled out")
    return 0 if ok else 1


def cmd_attest(a) -> int:
    from ids.detectors.integrity import attest, enroll
    man_path = Path(a.manifest)
    manifest = json.loads(man_path.read_text()) if man_path.exists() else {}
    key = load_key()
    if a.enroll:
        try:
            signed = enroll(a.file, manifest, key=key)
        except ValueError as e:
            print(f"refused: {e}")
            return 1
        man_path.write_text(json.dumps(signed, indent=2))
        print(f"enrolled {a.file} (manifest HMAC-signed)")
        return 0
    r = attest(a.file, manifest, key=key, require_signed=a.require_signed)
    print(json.dumps(r, indent=2))
    return 0 if r["ok"] else 1


def cmd_live(a) -> int:
    from ids.live import run_router
    try:
        thr, base, model = load_profile(a.profile)
    except (ValueError, OSError) as e:
        print(e)
        return 2
    log, rc = _open_log(a)
    if rc:
        return rc
    for n in startup_notices(thr, base, model):
        print(n)
    on_alert = _print_alert
    if a.dashboard:
        try:
            from ids.dashboard import Broadcaster, start_dashboard
        except ImportError:
            print("dashboard needs the web extra: pip install -e .[web]")
            return 2
        bc = Broadcaster()
        start_dashboard(bc, a.dashboard)
        print(f"dashboard: http://127.0.0.1:{a.dashboard}/")

        def on_alert(al: Alert) -> None:
            _print_alert(al)
            bc.push(al)
    try:
        eng = _engine_from_args(a, thr, base, model, log, on_alert)
    except ValueError as e:
        print(e)
        return 2
    print(f"IDS router: vehicle={a.master} gcs={a.gcs} (Ctrl+C to stop)")
    try:
        run_router(a.master, a.gcs, eng)
    except KeyboardInterrupt:
        pass
    return 0


def cmd_attack(a) -> int:
    from ids.live import send_attack
    print(f"sent {send_attack(a.target, a.kind, a.duration)} messages ({a.kind})")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ids", description="Drone Intrusion Detection System")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("calibrate", help="derive thresholds + integrity baseline from a benign log")
    c.add_argument("log"); c.add_argument("--out", required=True)
    c.add_argument("--frac", type=float, default=1.0); c.add_argument("--ml", action="store_true")
    c.set_defaults(fn=cmd_calibrate)
    r = sub.add_parser("replay", help="run the IDS over a .tlog, optionally injecting attacks")
    r.add_argument("log"); r.add_argument("--profile"); r.add_argument("--attack", action="append")
    r.add_argument("--log", dest="log_out"); r.add_argument("--max-seconds", type=float)
    _add_identity_opts(r)
    r.set_defaults(fn=cmd_replay)
    b = sub.add_parser("bench", help="reproducible benchmark (accuracy, FPR, latency, compute)")
    b.add_argument("log"); b.add_argument("--out", required=True)
    b.add_argument("--n", type=int, default=5); b.add_argument("--seed", type=int, default=7)
    b.add_argument("--ml", action="store_true")
    b.set_defaults(fn=cmd_bench)
    v = sub.add_parser("verify-log", help="verify a signed alert log")
    v.add_argument("file"); v.add_argument("--anchor", metavar="FILE", help="signed head anchor written by --anchor")
    v.set_defaults(fn=cmd_verify)
    t = sub.add_parser("attest", help="check a firmware image against a golden manifest")
    t.add_argument("file"); t.add_argument("--manifest", required=True); t.add_argument("--enroll", action="store_true")
    t.add_argument("--require-signed", action="store_true", help="fail if the manifest carries no valid signature")
    t.set_defaults(fn=cmd_attest)
    lv = sub.add_parser("live", help="inline MAVLink router with live detection")
    lv.add_argument("--master", default="tcp:127.0.0.1:5760"); lv.add_argument("--gcs", default="udpin:0.0.0.0:14550")
    lv.add_argument("--profile"); lv.add_argument("--log", dest="log_out")
    lv.add_argument("--dashboard", type=int, metavar="PORT", help="serve a live alert dashboard on this port")
    _add_identity_opts(lv)
    lv.set_defaults(fn=cmd_live)
    at = sub.add_parser("attack", help="send a live attack (lab/SITL use only)")
    at.add_argument("kind", choices=["inject", "flood", "rogue_heartbeat"])
    at.add_argument("--target", default="udpout:127.0.0.1:14550"); at.add_argument("--duration", type=float, default=5.0)
    at.set_defaults(fn=cmd_attack)
    return p


def main(argv=None) -> int:
    a = build_parser().parse_args(argv)
    return a.fn(a)
