"""Campaign manager — orchestrates scans across multiple targets.

The :class:`CampaignManager` wraps :class:`RedSimulatorPipeline` and runs
it against every target defined in a :class:`CampaignConfig`.  Targets can
be processed sequentially or in parallel (up to ``max_parallel`` threads).

A single target failing never crashes the entire campaign: the error is
captured in the corresponding :class:`TargetResult` and execution continues
with the remaining targets.
"""

from __future__ import annotations

import json
import time
from collections import Counter
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from src.infra.config import settings
from src.infra.decorators import logged, timed
from src.infra.logging import get_logger

from .models import CampaignConfig, CampaignResult, TargetConfig, TargetResult

logger = get_logger(__name__)


class CampaignManager:
    """Orchestrates scans across multiple targets."""

    def __init__(self, config: CampaignConfig) -> None:
        self.config = config
        self.result = CampaignResult(config=config)
        self._on_progress: Callable | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @logged
    @timed
    def run(self, on_progress: Callable | None = None) -> CampaignResult:
        """Run the campaign against all targets.

        If ``parallel=True``, runs up to ``max_parallel`` targets concurrently
        using :class:`ThreadPoolExecutor`.  Otherwise runs sequentially.

        Parameters
        ----------
        on_progress:
            Optional callback ``(target_name: str, status: str, detail: str) -> None``
            invoked at key moments (start, completion, failure) for each target.

        Returns
        -------
        CampaignResult
            Aggregated results for all targets.
        """
        self._on_progress = on_progress
        self.result.status = "running"

        max_parallel = min(
            self.config.max_parallel,
            settings.campaign_max_parallel,
        )

        logger.info(
            "Campaign '%s' starting — %d target(s), parallel=%s, max_parallel=%d",
            self.config.name,
            len(self.config.targets),
            self.config.parallel,
            max_parallel,
        )

        if self.config.parallel and len(self.config.targets) > 1:
            self._run_parallel(max_parallel)
        else:
            self._run_sequential()

        # Final status
        has_failure = any(r.status == "failed" for r in self.result.results)
        has_success = any(r.status == "completed" for r in self.result.results)
        if has_success and has_failure:
            self.result.status = "partial"
        elif has_failure:
            self.result.status = "failed"
        else:
            self.result.status = "completed"

        logger.info(
            "Campaign '%s' finished — status=%s, summary=%s",
            self.config.name,
            self.result.status,
            self.result.summary,
        )

        return self.result

    def generate_campaign_report(self) -> str:
        """Generate an aggregated Markdown report across all targets.

        The report includes:
        - A summary table (target | vulns found | successful attacks | status)
        - Per-target detailed sections
        - Cross-target analysis (common vulnerability types)

        Returns
        -------
        str
            Markdown-formatted campaign report.
        """
        lines: list[str] = []
        summary = self.result.summary

        # ── Header ──
        lines.append(f"# Campaign Report: {self.config.name}")
        lines.append("")
        lines.append(f"**Status:** {self.result.status}")
        lines.append(f"**Created:** {self.config.created_at}")
        lines.append(f"**Targets:** {summary['total_targets']}")
        lines.append(f"**Completed:** {summary['completed']} | **Failed:** {summary['failed']}")
        lines.append("")

        # ── Summary table ──
        lines.append("## Summary")
        lines.append("")
        lines.append("| Target | URL | Vulns Found | Successful Attacks | Duration (ms) | Status |")
        lines.append("|--------|-----|-------------|-------------------|---------------|--------|")

        for tr in self.result.results:
            vulns = tr.attack_result.get("total_attempts", 0) if tr.attack_result else 0
            successes = tr.attack_result.get("successful_attacks", 0) if tr.attack_result else 0
            status_icon = {
                "completed": "OK",
                "failed": "FAIL",
                "running": "...",
                "pending": "-",
            }.get(tr.status, tr.status)
            lines.append(
                f"| {tr.target.name} | {tr.target.url} | {vulns} | "
                f"{successes} | {tr.duration_ms:.0f} | {status_icon} |"
            )

        lines.append("")

        # ── Per-target details ──
        lines.append("## Per-Target Details")
        lines.append("")

        for tr in self.result.results:
            lines.append(f"### {tr.target.name}")
            lines.append("")
            lines.append(f"- **URL:** {tr.target.url}")
            lines.append(f"- **Status:** {tr.status}")
            lines.append(f"- **Duration:** {tr.duration_ms:.0f} ms")
            if tr.target.tags:
                lines.append(f"- **Tags:** {', '.join(tr.target.tags)}")

            if tr.error:
                lines.append(f"- **Error:** {tr.error}")

            if tr.scan_result:
                endpoints = tr.scan_result.get("endpoints", [])
                lines.append(f"- **Endpoints discovered:** {len(endpoints)}")

            if tr.attack_result:
                lines.append(f"- **Total attempts:** {tr.attack_result.get('total_attempts', 0)}")
                lines.append(
                    f"- **Successful attacks:** {tr.attack_result.get('successful_attacks', 0)}"
                )

            if tr.report:
                lines.append("")
                lines.append("<details>")
                lines.append(f"<summary>Full report for {tr.target.name}</summary>")
                lines.append("")
                lines.append(tr.report)
                lines.append("")
                lines.append("</details>")

            lines.append("")

        # ── Cross-target analysis ──
        lines.append("## Cross-Target Analysis")
        lines.append("")

        vuln_counter: Counter[str] = Counter()
        for tr in self.result.results:
            if tr.status != "completed" or not tr.attack_result:
                continue
            for single in tr.attack_result.get("results", []):
                if single.get("success"):
                    vuln_type = single.get("vector_id", "unknown")
                    vuln_counter[vuln_type] += 1

        if vuln_counter:
            lines.append("### Common Vulnerability Types")
            lines.append("")
            lines.append("| Vulnerability Type | Occurrences Across Targets |")
            lines.append("|-------------------|---------------------------|")
            for vuln_type, count in vuln_counter.most_common():
                lines.append(f"| {vuln_type} | {count} |")
            lines.append("")
        else:
            lines.append("No successful attacks detected across targets.")
            lines.append("")

        # ── Targets sharing the same vulnerabilities ──
        vuln_to_targets: dict[str, list[str]] = {}
        for tr in self.result.results:
            if tr.status != "completed" or not tr.attack_result:
                continue
            for single in tr.attack_result.get("results", []):
                if single.get("success"):
                    vid = single.get("vector_id", "unknown")
                    vuln_to_targets.setdefault(vid, []).append(tr.target.name)

        shared = {v: ts for v, ts in vuln_to_targets.items() if len(ts) > 1}
        if shared:
            lines.append("### Vulnerabilities Found in Multiple Targets")
            lines.append("")
            for vid, targets in shared.items():
                lines.append(f"- **{vid}**: {', '.join(targets)}")
            lines.append("")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _run_sequential(self) -> None:
        """Execute targets one after the other."""
        for target in self.config.targets:
            result = self._run_single_target(target)
            self.result.results.append(result)

    def _run_parallel(self, max_workers: int) -> None:
        """Execute targets in parallel using a thread pool."""
        futures_map = {}
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            for target in self.config.targets:
                future = pool.submit(self._run_single_target, target)
                futures_map[future] = target

            for future in as_completed(futures_map):
                target = futures_map[future]
                try:
                    result = future.result()
                except Exception as exc:
                    # Should not happen since _run_single_target catches all
                    # errors, but guard defensively.
                    logger.error("Unexpected error for target %s: %s", target.url, exc)
                    result = TargetResult(
                        target=target,
                        status="failed",
                        error=str(exc),
                    )
                self.result.results.append(result)

    def _run_single_target(self, target: TargetConfig) -> TargetResult:
        """Run the full pipeline against a single target.

        Errors are captured in the returned :class:`TargetResult` — this
        method never raises.
        """
        tr = TargetResult(target=target, status="running")
        self._notify(target.name, "running", "Pipeline started")

        start = time.perf_counter()
        try:
            from src.orchestrator import RedSimulatorPipeline

            pipeline = RedSimulatorPipeline(
                target_url=target.url,
                passive_scan=True,
            )
            report = pipeline.run(use_fixtures=self.config.use_fixtures)

            # Capture structured results as dicts for serialization
            tr.scan_result = (
                json.loads(pipeline.scan_result.model_dump_json()) if pipeline.scan_result else None
            )
            tr.attack_plan = (
                json.loads(pipeline.attack_plan.model_dump_json()) if pipeline.attack_plan else None
            )
            tr.attack_result = (
                json.loads(pipeline.attack_result.model_dump_json())
                if pipeline.attack_result
                else None
            )
            tr.report = report
            tr.status = "completed"

            self._notify(target.name, "completed", "Pipeline finished")
            logger.info("Target '%s' completed successfully", target.name)

        except Exception as exc:
            tr.status = "failed"
            tr.error = f"{type(exc).__name__}: {exc}"
            self._notify(target.name, "failed", tr.error)
            logger.error("Target '%s' failed: %s", target.name, exc, exc_info=True)

        tr.duration_ms = (time.perf_counter() - start) * 1000
        return tr

    def _notify(self, target_name: str, status: str, detail: str) -> None:
        """Fire the progress callback if one is registered."""
        if self._on_progress:
            try:
                self._on_progress(target_name, status, detail)
            except Exception:
                logger.warning("Progress callback failed", exc_info=True)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save_results(self, output_dir: Path | None = None) -> Path:
        """Save campaign results and report to disk.

        Parameters
        ----------
        output_dir:
            Directory to write into.  Defaults to ``data/campaigns/<name>/``.

        Returns
        -------
        Path
            The directory where files were saved.
        """
        if output_dir is None:
            base = Path(__file__).parent.parent.parent / "data" / "campaigns"
            safe_name = self.config.name.replace(" ", "_").lower()
            output_dir = base / safe_name

        output_dir.mkdir(parents=True, exist_ok=True)

        # Campaign report
        report_md = self.generate_campaign_report()
        (output_dir / "campaign_report.md").write_text(report_md)

        # Summary JSON
        summary_data = {
            "config": {
                "name": self.config.name,
                "targets": [
                    {"url": t.url, "name": t.name, "tags": t.tags} for t in self.config.targets
                ],
                "parallel": self.config.parallel,
                "created_at": self.config.created_at,
            },
            "status": self.result.status,
            "summary": self.result.summary,
            "targets": [],
        }
        for tr in self.result.results:
            summary_data["targets"].append(
                {
                    "name": tr.target.name,
                    "url": tr.target.url,
                    "status": tr.status,
                    "error": tr.error,
                    "duration_ms": tr.duration_ms,
                    "attack_result_summary": {
                        "total_attempts": (
                            tr.attack_result.get("total_attempts", 0) if tr.attack_result else 0
                        ),
                        "successful_attacks": (
                            tr.attack_result.get("successful_attacks", 0) if tr.attack_result else 0
                        ),
                    },
                }
            )

        (output_dir / "campaign_summary.json").write_text(
            json.dumps(summary_data, indent=2, default=str)
        )

        # Per-target individual reports
        for tr in self.result.results:
            if tr.report:
                safe_target = tr.target.name.replace(" ", "_").lower()
                (output_dir / f"report_{safe_target}.md").write_text(tr.report)

        logger.info("Campaign results saved to %s", output_dir)
        return output_dir
