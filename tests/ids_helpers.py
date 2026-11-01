from ids.core import Msg


class Stream:
    """Builds Msgs with a per-source auto-incrementing MAVLink sequence number."""

    def __init__(self):
        self.seq = {}

    def __call__(self, t, type, /, src=(1, 1), seq=None, **fields):
        if seq is None:
            seq = (self.seq.get(src, -1) + 1) % 256
        self.seq[src] = seq
        return Msg(t=t, type=type, src_sys=src[0], src_comp=src[1], seq=seq, fields=fields)


def hb(s, t, armed=True, src=(1, 1)):
    return s(t, "HEARTBEAT", src=src, type=2, autopilot=3, base_mode=(128 if armed else 0) | 1, custom_mode=0, system_status=4)


def gcs_hb(s, t, src=(255, 0)):
    return s(t, "HEARTBEAT", src=src, type=6, autopilot=8, base_mode=0, custom_mode=0, system_status=0)


def gpi(s, t, lat=-35.0, lon=149.0, alt_m=600.0, rel_m=20.0, vx=0, vy=0, hdg=0):
    return s(t, "GLOBAL_POSITION_INT", lat=int(lat * 1e7), lon=int(lon * 1e7), alt=int(alt_m * 1000),
             relative_alt=int(rel_m * 1000), vx=vx, vy=vy, vz=0, hdg=hdg)


def gps(s, t, lat=-35.0, lon=149.0, alt_m=600.0, vel_cms=0, fix=3, sats=10):
    return s(t, "GPS_RAW_INT", lat=int(lat * 1e7), lon=int(lon * 1e7), alt=int(alt_m * 1000), vel=vel_cms,
             fix_type=fix, eph=100, epv=100, cog=0, satellites_visible=sats)
