"""Campaign module — multi-target orchestration for RedSimulator.

Allows scanning multiple targets in a single campaign, with aggregated
results and per-target reports.

Usage::

    from src.campaign import CampaignManager
    from src.campaign.models import CampaignConfig, TargetConfig

    config = CampaignConfig(
        name="My Campaign",
        targets=[
            TargetConfig(url="http://target1:3000", name="App A"),
            TargetConfig(url="http://target2:3000", name="App B"),
        ],
        parallel=True,
    )
    manager = CampaignManager(config)
    result = manager.run()
    print(result.summary)
"""

from src.campaign.manager import CampaignManager

__all__ = ["CampaignManager"]
