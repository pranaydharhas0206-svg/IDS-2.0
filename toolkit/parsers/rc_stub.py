"""Remote controller acquisition/parser — architected extension point, not implemented.

Physical acquisition from an RC unit (internal flash/eMMC, often requiring a
write-blocker and, on some units, chip-off or JTAG) requires physical
hardware access that was not available for this submission window. See
docs/design_document.md for the planned physical acquisition workflow.
"""

from __future__ import annotations

from toolkit.parsers.base import NotImplementedParser


class RemoteControllerParser(NotImplementedParser):
    platform_name = "remote_controller"
    reason = (
        "Remote controller physical acquisition/parsing is architected but "
        "not implemented: no physical RC hardware was available for this "
        "submission window. Planned workflow documented in "
        "docs/design_document.md."
    )
