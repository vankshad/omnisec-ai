"""
Example: Quick security scan with OmniSec AI
"""

import asyncio
from src.core.orchestrator import AIOrchestrator, ModelConfig, ModelProvider
from src.core.engine import OmniSecEngine, ScanTarget


async def example_scan():
    """Run a quick scan example."""

    # Configure AI models
    configs = {
        ModelProvider.MIMO: ModelConfig(
            provider=ModelProvider.MIMO,
            api_key="your-mimo-key",
            base_url="https://api.xiaomimimo.com/v1",
            model_name="mimo-v2.5-pro",
        ),
        ModelProvider.CLAUDE: ModelConfig(
            provider=ModelProvider.CLAUDE,
            api_key="your-claude-key",
            base_url="https://api.anthropic.com/v1",
            model_name="claude-sonnet-4-20250514",
        ),
    }

    # Initialize
    orchestrator = AIOrchestrator(configs)
    await orchestrator.initialize()

    engine = OmniSecEngine(orchestrator, output_dir="./output")

    # Run scan
    target = ScanTarget(
        url="https://example.com",
        mode="quick",  # quick | full | recon-only
    )

    result = await engine.run(target)

    print(f"\n✅ Scan Complete!")
    print(f"   Target: {result.target}")
    print(f"   Findings: {len(result.findings)}")
    print(f"   Report: {result.report_path}")
    print(f"   AI Tokens: {result.ai_usage.get('total_tokens', 0)}")

    await orchestrator.shutdown()


if __name__ == "__main__":
    asyncio.run(example_scan())
