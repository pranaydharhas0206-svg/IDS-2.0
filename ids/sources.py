"""MAVLink message sources: pymavlink messages normalised into `Msg`."""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

from pymavlink import mavutil

from ids.core import Msg


def from_mavlink(m, t: float) -> Msg:
    typ = m.get_type()
    if typ == "BAD_DATA":
        return Msg(t=t, type="BAD_DATA", src_sys=0, src_comp=0, seq=0)
    fields = m.to_dict()
    fields.pop("mavpackettype", None)
    return Msg(t=t, type=typ, src_sys=m.get_srcSystem(), src_comp=m.get_srcComponent(),
               seq=m.get_seq(), fields=fields)


def iter_tlog(path: str | Path) -> Iterator[Msg]:
    conn = mavutil.mavlink_connection(str(path))
    try:
        while True:
            m = conn.recv_match()
            if m is None:
                return
            yield from_mavlink(m, float(getattr(m, "_timestamp", 0.0)))
    finally:
        conn.close()


def load_tlog(path: str | Path) -> list[Msg]:
    return list(iter_tlog(path))
