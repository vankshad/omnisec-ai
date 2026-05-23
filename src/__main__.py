"""
OmniSec AI — CLI Entry Point

Usage:
    python -m omnisec --target example.com --mode full
    python -m omnisec --target example.com --mode quick --output ./reports
"""

import argparse
import asyncio
import sys
from pathlib import Path

from .core.orchestrator import AIOrchestrator, ModelConfig, ModelProvider
from .core.engine import OmniSecEngine, ScanTarget
from .utils.logger import setup_logger
from .utils.helpers import load_config, validate_target


def parse_args():
    parser = argparse.ArgumentParser(
        prog="omnisec",
        description="OmniSec AI — Autonomous Security Testing Framework",
    )
    parser.add_argument("-t", "--target", required=True, help="Target URL or domain")
    parser.add_argument("-m", "--mode", choices=["full", "quick", "recon-only"], default="full")
    parser.add_argument("-o", "--output", default="./output", help="Output directory")
    parser.add_argument("-c", "--config", default="config/.env", help="Config file path")
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default="INFO")
    parser.add_argument("--model", choices=["claude", "gpt4", "mimo", "gemini"], help="Preferred AI model")
    return parser.parse_args()


async def main():
    args = parse_args()
    logger = setup_logger(args.log_level)

    logger.info("=" * 50)
    logger.info("  OmniSec AI — Autonomous Security Testing")
    logger.info("=" * 50)

    # Validate target
    try:
        target_url = validate_target(args.target)
    except ValueError as e:
        logger.error(f"Invalid target: {e}")
        sys.exit(1)

    # Load config
    try:
        config = load_config(args.config)
    except FileNotFoundError:
        logger.warning(f"Config not found at {args.config}, using env vars")
        config = {}

    # Initialize AI orchestrator
    model_configs = {}

    if claude_key := config.get("CLAUDE_API_KEY") or config.get("ANTHROPIC_API_KEY"):
        model_configs[ModelProvider.CLAUDE] = ModelConfig(
            provider=ModelProvider.CLAUDE,
            api_key=claude_key,
            base_url="https://api.anthropic.com/v1",
            model_name="claude-sonnet-4-20250514",
        )

    if openai_key := config.get("OPENAI_API_KEY"):
        model_configs[ModelProvider.GPT4] = ModelConfig(
            provider=ModelProvider.GPT4,
            api_key=openai_key,
            base_url="https://api.openai.com/v1",
            model_name="gpt-4o",
        )

    if mimo_key := config.get("MIMO_API_KEY"):
        model_configs[ModelProvider.MIMO] = ModelConfig(
            provider=ModelProvider.MIMO,
            api_key=mimo_key,
            base_url="https://api.xiaomimimo.com/v1",
            model_name="mimo-v2.5-pro",
        )

    if not model_configs:
        logger.error("No AI API keys configured. Set at least one in config/.env")
        sys.exit(1)

    logger.info(f"Initialized {len(model_configs)} AI providers: {list(model_configs.keys())}")

    # Initialize orchestrator & engine
    orchestrator = AIOrchestrator(model_configs)
    await orchestrator.initialize()

    engine = OmniSecEngine(orchestrator, output_dir=args.output)

    # Run scan
    target = ScanTarget(url=target_url, mode=args.mode)

    try:
        result = await engine.run(target)

        logger.info("=" * 50)
        logger.info("  SCAN COMPLETE")
        logger.info(f"  Target: {result.target}")
        logger.info(f"  Findings: {len(result.findings)}")
        logger.info(f"  Report: {result.report_path}")
        logger.info(f"  AI Tokens Used: {result.ai_usage.get('total_tokens', 0)}")
        logger.info("=" * 50)
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        raise
    finally:
        await orchestrator.shutdown()


def run():
    """Entry point for CLI."""
    asyncio.run(main())


if __name__ == "__main__":
    run()
