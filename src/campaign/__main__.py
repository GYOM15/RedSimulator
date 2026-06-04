"""CLI entry point for multi-target campaign execution.

Usage::

    # Run against multiple targets by URL
    python -m src.campaign --targets http://app1:3000,http://app2:3000

    # Run from a campaign config JSON file
    python -m src.campaign --config campaign.json

    # Use fixtures mode (no live scanning)
    python -m src.campaign --targets http://app1:3000 --fixtures

    # Parallel execution with custom parallelism
    python -m src.campaign --targets http://a:3000,http://b:3000 --parallel --max-parallel 5

Campaign config JSON format::

    {
        "name": "My Campaign",
        "targets": [
            {"url": "http://app1:3000", "name": "App A", "tags": ["prod"]},
            {"url": "http://app2:3000", "name": "App B", "tags": ["staging"]}
        ],
        "parallel": true,
        "max_parallel": 3,
        "use_fixtures": false
    }
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from src.infra.config import settings
from src.infra.logging import get_logger, setup_logging

from .manager import CampaignManager
from .models import CampaignConfig, TargetConfig

logger = get_logger(__name__)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="RedSimulator — Multi-target campaign execution",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--targets",
        type=str,
        help="Comma-separated list of target URLs (e.g. http://a:3000,http://b:3000)",
    )
    group.add_argument(
        "--config",
        type=str,
        help="Path to a campaign configuration JSON file",
    )
    parser.add_argument(
        "--name",
        type=str,
        default="CLI Campaign",
        help="Campaign name (default: 'CLI Campaign')",
    )
    parser.add_argument(
        "--fixtures",
        action="store_true",
        help="Use fixtures instead of live scanning",
    )
    parser.add_argument(
        "--parallel",
        action="store_true",
        help="Run targets in parallel",
    )
    parser.add_argument(
        "--max-parallel",
        type=int,
        default=3,
        help="Maximum number of targets to scan in parallel (default: 3)",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="Directory to save campaign results (default: data/campaigns/<name>/)",
    )
    return parser.parse_args()


def _build_config_from_args(args: argparse.Namespace) -> CampaignConfig:
    """Build a CampaignConfig from CLI arguments."""
    if args.config:
        config_path = Path(args.config)
        if not config_path.exists():
            logger.error("Config file not found: %s", config_path)
            sys.exit(1)

        data = json.loads(config_path.read_text())
        targets = [
            TargetConfig(
                url=t["url"],
                name=t.get("name", ""),
                auth_type=t.get("auth_type", "none"),
                auth_credentials=t.get("auth_credentials", {}),
                tags=t.get("tags", []),
            )
            for t in data["targets"]
        ]
        return CampaignConfig(
            name=data.get("name", args.name),
            targets=targets,
            parallel=data.get("parallel", args.parallel),
            max_parallel=data.get("max_parallel", args.max_parallel),
            use_fixtures=data.get("use_fixtures", args.fixtures),
        )

    # Build from --targets flag
    urls = [u.strip() for u in args.targets.split(",") if u.strip()]
    if not urls:
        logger.error("No valid target URLs provided")
        sys.exit(1)

    targets = [TargetConfig(url=url) for url in urls]
    return CampaignConfig(
        name=args.name,
        targets=targets,
        parallel=args.parallel,
        max_parallel=args.max_parallel,
        use_fixtures=args.fixtures,
    )


def _on_progress(target_name: str, status: str, detail: str) -> None:
    """CLI progress callback — prints status updates."""
    logger.info("[CAMPAIGN] %s — %s: %s", target_name, status, detail)


def main() -> None:
    setup_logging(settings.log_level, settings.log_format)

    args = _parse_args()
    config = _build_config_from_args(args)

    logger.info(
        "Starting campaign '%s' with %d target(s)",
        config.name,
        len(config.targets),
    )

    manager = CampaignManager(config)
    result = manager.run(on_progress=_on_progress)

    # Save results
    output_dir = Path(args.output_dir) if args.output_dir else None
    saved_to = manager.save_results(output_dir=output_dir)

    # Print summary
    summary = result.summary
    logger.info("Campaign complete — %s", summary)
    logger.info("Results saved to %s", saved_to)

    # Print the campaign report to stdout
    report = manager.generate_campaign_report()
    print(report)


if __name__ == "__main__":
    main()
