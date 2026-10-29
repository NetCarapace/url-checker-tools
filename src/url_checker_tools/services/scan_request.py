"""Immutable scan request built once from the parsed CLI arguments."""

from dataclasses import dataclass
from typing import Optional, Sequence, Tuple


@dataclass(frozen=True)
class ScanRequest:
    """Everything a scan needs, isolated from argparse."""

    target: str
    providers: Tuple[str, ...]
    session_id: str
    format: str
    raw: bool
    robot: bool
    verbose: bool
    log: bool
    score: bool
    score_detail: bool
    misp_report: bool
    auto_scan_files: bool
    download: bool
    workflow: Optional[str]

    @classmethod
    def from_args(
        cls, args, providers: Sequence[str], session_id: str
    ) -> "ScanRequest":
        """Build a request from parsed arguments (after robot mode flags are applied)."""
        return cls(
            target=args.target,
            providers=tuple(providers),
            session_id=session_id,
            format=args.format,
            raw=args.raw,
            robot=args.robot,
            verbose=args.verbose,
            log=args.log,
            score=args.score,
            score_detail=getattr(args, "score_detail", False),
            misp_report=args.misp_report,
            auto_scan_files=args.auto_scan_files,
            download=args.download,
            workflow=args.workflow,
        )
