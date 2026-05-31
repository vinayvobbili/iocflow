"""A :class:`Source` that watches a directory for text files to triage.

Drop an advisory / report / alert as a ``.txt`` (or any text glob) into a
directory and the next poll picks it up. The dedup id is the path + mtime, so an
edited-and-re-saved file is re-processed; an untouched one is not. Stdlib only.
"""
from __future__ import annotations

import glob
import os
from typing import List

from iocflow.sources.models import Trigger


class FileSource:
    """Emits a trigger for each file matching ``pattern`` under ``path``.

    Args:
        path: directory to scan.
        pattern: glob (default ``*.txt``).
        recursive: recurse into subdirectories.
        encoding: text encoding (errors are ignored).
        name: source name.
    """

    def __init__(
        self,
        path: str,
        *,
        pattern: str = "*.txt",
        recursive: bool = False,
        encoding: str = "utf-8",
        name: str = "file",
    ) -> None:
        self.path = path
        self.pattern = pattern
        self.recursive = recursive
        self.encoding = encoding
        self.name = name

    def _paths(self) -> List[str]:
        if self.recursive:
            return sorted(glob.glob(os.path.join(self.path, "**", self.pattern), recursive=True))
        return sorted(glob.glob(os.path.join(self.path, self.pattern)))

    def poll(self) -> List[Trigger]:
        triggers: List[Trigger] = []
        for fp in self._paths():
            if not os.path.isfile(fp):
                continue
            try:
                mtime = int(os.path.getmtime(fp))
                text = open(fp, encoding=self.encoding, errors="ignore").read()
            except OSError:
                continue
            triggers.append(Trigger(
                source=self.name,
                id=f"{fp}@{mtime}",
                text=text,
                title=os.path.basename(fp),
                url=f"file://{os.path.abspath(fp)}",
                meta={"path": fp, "mtime": mtime},
            ))
        return triggers
