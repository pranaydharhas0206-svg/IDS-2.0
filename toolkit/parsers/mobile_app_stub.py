"""Companion mobile app data parser — architected extension point, not implemented.

Companion apps (e.g. DJI Fly, Litchi) cache flight records and cached media
in per-app SQLite databases / JSON on the mobile device. Acquiring this
forensically requires either a logical extraction (ADB backup / iTunes
backup) or an MDM/forensic imaging tool, neither of which was available for
this submission window. See docs/design_document.md for the planned
acquisition and parsing approach.
"""

from __future__ import annotations

from toolkit.parsers.base import NotImplementedParser


class MobileAppParser(NotImplementedParser):
    platform_name = "mobile_app"
    reason = (
        "Companion mobile app extraction/parsing is architected but not "
        "implemented: no test device/backup was available for this "
        "submission window. Planned approach documented in "
        "docs/design_document.md."
    )
