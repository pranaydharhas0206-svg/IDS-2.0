"""Command-line entry point.

    toolkit init-case   --case-dir <dir> --examiner <name> [--description <text>]
    toolkit acquire     --case-dir <dir> --source <file> --platform <platform> --examiner <name>
    toolkit carve       --case-dir <dir> --source <image> --examiner <name>
    toolkit analyze     --case-dir <dir> [--evidence-id <id>]
    toolkit report      --case-dir <dir> [--output <file>]
    toolkit verify      --case-dir <dir>
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from toolkit import __version__
from toolkit import service


def cmd_init_case(args: argparse.Namespace) -> None:
    case_dir = Path(args.case_dir)
    case = service.init_case(case_dir, examiner=args.examiner, description=args.description or "")
    print(f"Case created: {case.case_id}")
    print(f"Case directory: {case_dir.resolve()}")


def cmd_acquire(args: argparse.Namespace) -> None:
    case_dir = Path(args.case_dir)
    try:
        evidence = service.acquire_evidence(
            case_dir, Path(args.source), platform=args.platform,
            examiner=args.examiner, description=args.description or "",
        )
    except service.ToolkitError as exc:
        sys.exit(str(exc))
    print(f"Evidence acquired: {evidence.evidence_id}")
    print(f"SHA-256: {evidence.sha256}")


def cmd_carve(args: argparse.Namespace) -> None:
    case_dir = Path(args.case_dir)
    try:
        carved = service.carve_evidence(
            case_dir, Path(args.source), examiner=args.examiner,
        )
    except service.ToolkitError as exc:
        sys.exit(str(exc))
    print(f"Carved {len(carved)} file(s) from '{Path(args.source).name}':")
    for cf in carved:
        print(f"  [{cf.file_type}] offset={cf.offset} size={cf.size} "
              f"sha256={cf.sha256} -> {cf.output_path.name}")


def cmd_analyze(args: argparse.Namespace) -> None:
    case_dir = Path(args.case_dir)
    try:
        outcomes = service.analyze_case(
            case_dir, examiner=args.examiner, evidence_id=args.evidence_id,
        )
    except service.ToolkitError as exc:
        sys.exit(str(exc))

    status_text = {"OK": "OK", "PARTIAL": "PARTIAL", "NOT_IMPLEMENTED": "NOT IMPLEMENTED"}
    for outcome in outcomes:
        if outcome.status == "INTEGRITY_FAILURE":
            print(f"[!] INTEGRITY FAILURE for {outcome.evidence_id} — "
                  f"current hash does not match acquisition-time hash. Skipping.")
            continue
        if outcome.status == "PARSE_ERROR":
            print(f"[!] PARSE ERROR for {outcome.evidence_id} ({outcome.original_filename}) — "
                  f"{outcome.warnings[0] if outcome.warnings else 'could not be parsed'}. Skipping.")
            continue
        print(f"[{status_text[outcome.status]}] {outcome.original_filename} "
              f"({outcome.platform}): {outcome.event_count} events, "
              f"{outcome.track_point_count} track points")
        for w in outcome.warnings:
            print(f"    warning: {w}")


def cmd_report(args: argparse.Namespace) -> None:
    case_dir = Path(args.case_dir)
    try:
        result = service.generate_case_report(
            case_dir, examiner=args.examiner,
            output=Path(args.output) if args.output else None,
        )
    except service.ToolkitError as exc:
        sys.exit(str(exc))

    for s in result.skipped:
        print(f"[!] No analysis found for {s.evidence_id} ({s.original_filename}) — "
              f"run 'toolkit analyze' first. Skipping.")
    print(f"Report written to: {result.path.resolve()}")
    if result.pdf_path is not None:
        print(f"PDF report written to: {result.pdf_path.resolve()}")
    else:
        print("[!] PDF export failed; HTML report is still complete and verifiable.")


def cmd_verify(args: argparse.Namespace) -> None:
    case_dir = Path(args.case_dir)
    try:
        result = service.verify_case(case_dir)
    except service.ToolkitError as exc:
        sys.exit(str(exc))

    if result.custody_ok:
        print(f"Chain-of-custody log: OK ({result.entry_count} entries, hash chain intact)")
    else:
        print(f"Chain-of-custody log: BROKEN at entry #{result.broken_at}")

    status_text = {"OK": "OK", "HASH_MISMATCH": "HASH MISMATCH", "MISSING": "MISSING"}
    all_evidence_ok = True
    for ev in result.evidence:
        print(f"  [{status_text[ev.status]}] {ev.original_filename} ({ev.evidence_id})")
        if ev.status != "OK":
            all_evidence_ok = False

    if not (result.custody_ok and all_evidence_ok):
        sys.exit(1)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="toolkit", description="Drone Forensic Toolkit")
    p.add_argument("--version", action="version", version=f"toolkit {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init-case", help="Create a new forensic case")
    p_init.add_argument("--case-dir", required=True)
    p_init.add_argument("--examiner", required=True)
    p_init.add_argument("--description", default="")
    p_init.set_defaults(func=cmd_init_case)

    p_acq = sub.add_parser("acquire", help="Acquire evidence into a case with hashing")
    p_acq.add_argument("--case-dir", required=True)
    p_acq.add_argument("--source", required=True)
    p_acq.add_argument("--platform", required=True,
                        choices=["ardupilot", "dji", "px4", "remote_controller", "mobile_app"])
    p_acq.add_argument("--examiner", required=True)
    p_acq.add_argument("--description", default="")
    p_acq.set_defaults(func=cmd_acquire)

    p_carve = sub.add_parser("carve", help="Signature-carve media files from a raw disk/SD-card image")
    p_carve.add_argument("--case-dir", required=True)
    p_carve.add_argument("--source", required=True)
    p_carve.add_argument("--examiner", required=True)
    p_carve.set_defaults(func=cmd_carve)

    p_ana = sub.add_parser("analyze", help="Parse acquired evidence and extract timeline/flight path")
    p_ana.add_argument("--case-dir", required=True)
    p_ana.add_argument("--evidence-id", default=None)
    p_ana.add_argument("--examiner", required=True)
    p_ana.set_defaults(func=cmd_analyze)

    p_rep = sub.add_parser("report", help="Generate the forensic report")
    p_rep.add_argument("--case-dir", required=True)
    p_rep.add_argument("--output", default=None)
    p_rep.add_argument("--examiner", default=None)
    p_rep.set_defaults(func=cmd_report)

    p_ver = sub.add_parser("verify", help="Verify chain-of-custody log and evidence hashes")
    p_ver.add_argument("--case-dir", required=True)
    p_ver.set_defaults(func=cmd_verify)

    return p


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
