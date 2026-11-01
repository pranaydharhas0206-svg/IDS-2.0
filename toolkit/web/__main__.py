"""Entry point: `python -m toolkit.web` starts the local case-management GUI."""

from __future__ import annotations

import webbrowser

import uvicorn


def main() -> None:
    url = "http://127.0.0.1:8000"
    print(f"AeroXperts case-management GUI starting at {url}")
    webbrowser.open(url)
    uvicorn.run("toolkit.web.app:app", host="127.0.0.1", port=8000)


if __name__ == "__main__":
    main()
