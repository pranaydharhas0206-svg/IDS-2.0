from toolkit.parsers.base import BaseParser, ParserResult
from toolkit.parsers.ardupilot import ArduPilotParser
from toolkit.parsers.dji import DJIParser
from toolkit.parsers.px4 import PX4Parser
from toolkit.parsers.rc_stub import RemoteControllerParser
from toolkit.parsers.mobile_app_stub import MobileAppParser

REGISTRY = {
    "ardupilot": ArduPilotParser,
    "dji": DJIParser,
    "px4": PX4Parser,
    "remote_controller": RemoteControllerParser,
    "mobile_app": MobileAppParser,
}


def get_parser(platform: str) -> BaseParser:
    try:
        cls = REGISTRY[platform]
    except KeyError as exc:
        raise ValueError(
            f"Unknown platform '{platform}'. Supported: {sorted(REGISTRY)}"
        ) from exc
    return cls()


__all__ = ["BaseParser", "ParserResult", "get_parser", "REGISTRY"]
