"""
AI Model Orchestrator — Routes tasks to optimal AI models

Supports: Claude, GPT-4, MiMo V2.5, Gemini
Strategy: Each model has strengths; orchestrator picks the best fit.
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)


class ModelProvider(Enum):
    CLAUDE = "claude"
    GPT4 = "gpt4"
    MIMO = "mimo"
    GEMINI = "gemini"


class TaskType(Enum):
    RECON_ANALYSIS = "recon_analysis"
    VULN_DETECTION = "vuln_detection"
    EXPLOIT_DEV = "exploit_dev"
    CODE_REVIEW = "code_review"
    REPORT_GENERATION = "report_generation"
    REASONING = "reasoning"
    IMAGE_ANALYSIS = "image_analysis"


@dataclass
class ModelConfig:
    provider: ModelProvider
    api_key: str
    base_url: str
    model_name: str
    max_tokens: int = 4096
    temperature: float = 0.3
    cost_per_1k: float = 0.0


@dataclass
class AIResponse:
    model: str
    task: str
    content: str
    tokens_used: int
    latency_ms: float
    confidence: float


# Task → Model routing matrix
TASK_MODEL_MAP: dict[TaskType, list[ModelProvider]] = {
    TaskType.RECON_ANALYSIS: [ModelProvider.MIMO, ModelProvider.GPT4],
    TaskType.VULN_DETECTION: [ModelProvider.CLAUDE, ModelProvider.MIMO],
    TaskType.EXPLOIT_DEV: [ModelProvider.CLAUDE, ModelProvider.GPT4],
    TaskType.CODE_REVIEW: [ModelProvider.CLAUDE, ModelProvider.MIMO],
    TaskType.REPORT_GENERATION: [ModelProvider.CLAUDE, ModelProvider.GPT4],
    TaskType.REASONING: [ModelProvider.MIMO, ModelProvider.CLAUDE],
    TaskType.IMAGE_ANALYSIS: [ModelProvider.GEMINI, ModelProvider.GPT4],
}


class AIOrchestrator:
    """Routes security tasks to the optimal AI model."""

    def __init__(self, configs: dict[ModelProvider, ModelConfig]):
        self.configs = configs
        self.clients: dict[ModelProvider, httpx.AsyncClient] = {}
        self._usage_log: list[dict] = []

    async def initialize(self):
        """Initialize HTTP clients for each provider."""
        for provider, config in self.configs.items():
            self.clients[provider] = httpx.AsyncClient(
                base_url=config.base_url,
                headers={
                    "Authorization": f"Bearer {config.api_key}",
                    "Content-Type": "application/json",
                },
                timeout=60.0,
            )
        logger.info(f"Initialized {len(self.clients)} AI providers")

    async def route_task(
        self,
        task_type: TaskType,
        prompt: str,
        context: Optional[dict] = None,
        preferred_model: Optional[ModelProvider] = None,
    ) -> AIResponse:
        """Route a task to the best available AI model."""
        if preferred_model and preferred_model in self.configs:
            providers = [preferred_model]
        else:
            providers = TASK_MODEL_MAP.get(task_type, [ModelProvider.CLAUDE])

        last_error = None
        for provider in providers:
            if provider not in self.configs:
                continue
            try:
                return await self._call_model(provider, task_type.value, prompt, context)
            except Exception as e:
                logger.warning(f"{provider.value} failed: {e}")
                last_error = e
                continue

        raise RuntimeError(f"All models failed for {task_type.value}: {last_error}")

    async def _call_model(
        self,
        provider: ModelProvider,
        task: str,
        prompt: str,
        context: Optional[dict],
    ) -> AIResponse:
        """Call a specific AI model."""
        config = self.configs[provider]
        client = self.clients[provider]

        system_prompt = self._build_system_prompt(task, context)
        payload = self._build_payload(provider, config, system_prompt, prompt)

        import time
        start = time.monotonic()

        response = await client.post("/v1/chat/completions", json=payload)
        response.raise_for_status()
        data = response.json()

        latency = (time.monotonic() - start) * 1000
        content = data["choices"][0]["message"]["content"]
        tokens = data.get("usage", {}).get("total_tokens", 0)

        result = AIResponse(
            model=config.model_name,
            task=task,
            content=content,
            tokens_used=tokens,
            latency_ms=latency,
            confidence=0.85,
        )

        self._usage_log.append({
            "model": provider.value,
            "task": task,
            "tokens": tokens,
            "latency_ms": latency,
        })

        return result

    def _build_system_prompt(self, task: str, context: Optional[dict]) -> str:
        """Build task-specific system prompt."""
        base = "You are OmniSec AI, an expert security testing assistant."
        task_prompts = {
            "recon_analysis": f"{base} Analyze reconnaissance data and identify attack surfaces.",
            "vuln_detection": f"{base} Identify vulnerabilities with CVSS scoring and remediation.",
            "exploit_dev": f"{base} Develop proof-of-concept exploits for identified vulnerabilities.",
            "code_review": f"{base} Perform security-focused code review.",
            "report_generation": f"{base} Generate professional pentest reports.",
            "reasoning": f"{base} Apply chain-of-thought reasoning to security problems.",
        }
        prompt = task_prompts.get(task, base)
        if context:
            prompt += f"\n\nContext: {json.dumps(context)}"
        return prompt

    def _build_payload(
        self, provider: ModelProvider, config: ModelConfig, system: str, user: str
    ) -> dict:
        """Build API payload for each provider."""
        return {
            "model": config.model_name,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "max_tokens": config.max_tokens,
            "temperature": config.temperature,
        }

    def get_usage_stats(self) -> dict:
        """Return aggregated usage statistics."""
        total_tokens = sum(u["tokens"] for u in self._usage_log)
        by_model = {}
        for u in self._usage_log:
            m = u["model"]
            by_model.setdefault(m, {"calls": 0, "tokens": 0})
            by_model[m]["calls"] += 1
            by_model[m]["tokens"] += u["tokens"]
        return {"total_tokens": total_tokens, "total_calls": len(self._usage_log), "by_model": by_model}

    async def shutdown(self):
        """Close all HTTP clients."""
        for client in self.clients.values():
            await client.aclose()
