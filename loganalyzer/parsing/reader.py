import gzip
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from loganalyzer.domain.models import LogEntry
from loganalyzer.parsing.parser import ParseError, parse_line


@dataclass
class ParseStats:
    """Підсумок читання файлу."""

    total: int = 0
    parsed: int = 0
    errors: int = 0
    bad_lines: list[tuple[int, str]] = field(default_factory=list)  # перші кілька


def _open_text(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, encoding="utf-8", errors="replace")


def read_entries(path: str | Path, stats: ParseStats) -> Iterator[LogEntry]:
    """Читає файл по одному рядку. Биті рядки рахує, але не падає."""
    with _open_text(Path(path)) as file:
        for number, line in enumerate(file, start=1):
            if not line.strip():
                continue
            stats.total += 1
            try:
                entry = parse_line(line)
            except ParseError:
                stats.errors += 1
                if len(stats.bad_lines) < 5:
                    stats.bad_lines.append((number, line.strip()[:100]))
                continue
            stats.parsed += 1
            yield entry