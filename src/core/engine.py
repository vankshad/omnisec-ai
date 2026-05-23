"""
OmniSec Engine — Main execution engine

Orchestrates the full pentest pipeline:
Recon → Analysis → Exploitation → Reporting
"""

import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from .orchestrator import AIOrchestrator, ModelProvider, TaskType

logger = logging.getLogger(__name__)


@dataclass
class ScanTarget:
    url: str
    scope: list[str] = None
    exclude: list[str] = None
    mode: str = "full"  # full | quick | recon-only


@dataclass
class ScanResult:
    target: str
    start_time: datetime
    end_time: Optional[datetime]
    findings: list[dict]
    report_path: Optional[str]
    ai_usage: dict


class OmniSecEngine:
    """Main engine — runs the full security testing pipeline."""

    def __init__(self, orchestrator: AIOrchestrator, output_dir: str = "./output"):
        self.orchestrator = orchestrator
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def run(self, target: ScanTarget) -> ScanResult:
        """Execute full pentest pipeline."""
        logger.info(f"Starting scan: {target.url} (mode={target.mode})")
        start = datetime.now()
        findings = []

        # Phase 1: Reconnaissance
        if target.mode in ("full", "recon-only"):
            recon_findings = await self._phase_recon(target)
            findings.extend(recon_findings)

        # Phase 2: Vulnerability Analysis
        if target.mode in ("full", "quick"):
            vuln_findings = await self._phase_analyze(target, findings)
            findings.extend(vuln_findings)

        # Phase 3: Report Generation
        report_path = await self._phase_report(target, findings)

        end = datetime.now()
        usage = self.orchestrator.get_usage_stats()

        result = ScanResult(
            target=target.url,
            start_time=start,
            end_time=end,
            findings=findings,
            report_path=str(report_path),
            ai_usage=usage,
        )

        # Save result
        result_path = self.output_dir / f"scan_{datetime.now():%Y%m%d_%H%M%S}.json"
        result_path.write_text(json.dumps({
            "target": result.target,
            "start": result.start_time.isoformat(),
            "end": result.end_time.isoformat(),
            "findings_count": len(result.findings),
            "ai_usage": result.ai_usage,
        }, indent=2))

        logger.info(f"Scan complete: {len(findings)} findings, report: {report_path}")
        return result

    async def _phase_recon(self, target: ScanTarget) -> list[dict]:
        """Phase 1: AI-powered reconnaissance."""
        logger.info("Phase 1: Reconnaissance")

        # Subdomain enumeration
        subdomains = await self._enum_subdomains(target.url)

        # AI analysis of recon data
        response = await self.orchestrator.route_task(
            TaskType.RECON_ANALYSIS,
            f"Analyze these subdomains for {target.url} and identify high-value targets:\n"
            + "\n".join(subdomains),
            context={"target": target.url, "scope": target.scope},
        )

        findings = [{
            "phase": "recon",
            "type": "subdomain_analysis",
            "severity": "info",
            "data": response.content,
            "model": response.model,
        }]

        return findings

    async def _phase_analyze(self, target: ScanTarget, prior: list[dict]) -> list[dict]:
        """Phase 2: AI-powered vulnerability analysis."""
        logger.info("Phase 2: Vulnerability Analysis")

        recon_summary = json.dumps([f.get("data", "") for f in prior], indent=2)

        response = await self.orchestrator.route_task(
            TaskType.VULN_DETECTION,
            f"Based on this recon data, identify potential vulnerabilities:\n{recon_summary}",
            context={"target": target.url},
        )

        return [{
            "phase": "analysis",
            "type": "vulnerability_assessment",
            "severity": "medium",
            "data": response.content,
            "model": response.model,
        }]

    async def _phase_report(self, target: ScanTarget, findings: list[dict]) -> Path:
        """Phase 3: AI-powered report generation."""
        logger.info("Phase 3: Report Generation")

        findings_text = json.dumps(findings, indent=2, default=str)

        response = await self.orchestrator.route_task(
            TaskType.REPORT_GENERATION,
            f"Generate a professional pentest report for {target.url}:\n{findings_text}",
            context={"target": target.url, "findings_count": len(findings)},
        )

        report_path = self.output_dir / f"report_{datetime.now():%Y%m%d_%H%M%S}.md"
        report_path.write_text(response.content)
        return report_path

    async def _enum_subdomains(self, domain: str) -> list[str]:
        """Enumerate subdomains (placeholder — integrates with subfinder/amass)."""
        # In production, this calls subfinder/amass/dnsx
        logger.info(f"Enumerating subdomains for {domain}")
        return [f"api.{domain}", f"admin.{domain}", f"mail.{domain}", f"dev.{domain}"]
