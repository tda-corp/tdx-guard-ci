"""Console output: colours only on a terminal, messages on stderr in --json mode."""

from __future__ import annotations

import os
import sys
from typing import IO, Optional, Sequence

_CODES = {"bold": "1", "dim": "2", "red": "31", "green": "32", "yellow": "33", "blue": "34", "cyan": "36"}


class UI:
    def __init__(self, verbose: bool = False, json_mode: bool = False, stream: Optional[IO[str]] = None):
        self.verbose = verbose
        self.json_mode = json_mode
        # In --json mode stdout carries only the JSON document, everything else goes to stderr.
        self.stream = stream or (sys.stderr if json_mode else sys.stdout)
        self.color = _use_color(self.stream)

    def style(self, text: str, *styles: str) -> str:
        if not self.color or not styles:
            return text
        codes = ";".join(_CODES[s] for s in styles)
        return f"\033[{codes}m{text}\033[0m"

    def out(self, text: str = "") -> None:
        print(text, file=self.stream, flush=True)

    def step(self, text: str) -> None:
        self.out(self.style("> ", "cyan", "bold") + self.style(text, "bold"))

    def info(self, text: str) -> None:
        self.out("  " + text)

    def success(self, text: str) -> None:
        self.out(self.style("  ok ", "green", "bold") + text)

    def warn(self, text: str) -> None:
        self.out(self.style("  warning: ", "yellow", "bold") + text)

    def error(self, text: str, hint: str = "") -> None:
        print(self.style("error: ", "red", "bold") + text, file=sys.stderr, flush=True)
        if hint:
            print("       " + hint, file=sys.stderr, flush=True)

    def debug(self, text: str) -> None:
        if self.verbose:
            self.out(self.style("  " + text, "dim"))

    def table(self, headers: Sequence[str], rows: Sequence[Sequence[str]], align_right: Sequence[int] = ()) -> None:
        widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                widths[i] = max(widths[i], len(cell))

        def fmt(cells: Sequence[str]) -> str:
            parts = []
            for i, cell in enumerate(cells):
                parts.append(cell.rjust(widths[i]) if i in align_right else cell.ljust(widths[i]))
            return "  " + "  ".join(parts).rstrip()

        self.out(self.style(fmt(headers), "bold"))
        self.out("  " + "  ".join("-" * w for w in widths))
        for row in rows:
            self.out(fmt(row))


def _use_color(stream: IO[str]) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    if os.environ.get("TERM") == "dumb":
        return False
    try:
        return stream.isatty()
    except (AttributeError, ValueError):
        return False
