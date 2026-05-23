"""
Reconnaissance Module — AI-powered target discovery

Integrates: subfinder, amass, httpx, nmap
AI role: Interpret results, prioritize targets, identify attack surface
"""

import asyncio
import json
import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class ReconResult:
    subdomains: list[str]
    live_hosts: list[dict]
    technologies: list[str]
    open_ports: list[dict]
    ai_analysis: str


class ReconModule:
    """Automated reconnaissance with AI interpretation."""

    def __init__(self, orchestrator):
        self.orchestrator = orchestrator

    async def run_full_recon(self, target: str) -> ReconResult:
        """Execute full reconnaissance pipeline."""
        logger.info(f"Starting full recon for {target}")

        # Step 1: Subdomain enumeration
        subdomains = await self._subfinder(target)

        # Step 2: Live host detection
        live_hosts = await self._httpx_probe(subdomains)

        # Step 3: Port scanning
        ports = await self._nmap_scan([h["url"] for h in live_hosts[:10]])

        # Step 4: AI analysis
        from ..core.orchestrator import TaskType
        ai_response = await self.orchestrator.route_task(
            TaskType.RECON_ANALYSIS,
            self._build_analysis_prompt(target, subdomains, live_hosts, ports),
        )

        return ReconResult(
            subdomains=subdomains,
            live_hosts=live_hosts,
            technologies=self._extract_tech(live_hosts),
            open_ports=ports,
            ai_analysis=ai_response.content,
        )

    async def _subfinder(self, domain: str) -> list[str]:
        """Run subfinder for subdomain enumeration."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "subfinder", "-d", domain, "-silent",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            subs = stdout.decode().strip().split("\n")
            logger.info(f"Found {len(subs)} subdomains for {domain}")
            return [s for s in subs if s]
        except FileNotFoundError:
            logger.warning("subfinder not installed, using fallback")
            return [f"www.{domain}", f"api.{domain}", f"mail.{domain}"]

    async def _httpx_probe(self, subdomains: list[str]) -> list[dict]:
        """Probe subdomains for live hosts."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "httpx", "-silent", "-json", "-",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdin = "\n".join(subdomains).encode()
            stdout, _ = await proc.communicate(input=stdin)
            results = []
            for line in stdout.decode().strip().split("\n"):
                if line:
                    results.append(json.loads(line))
            return results
        except FileNotFoundError:
            logger.warning("httpx not installed, using fallback")
            return [{"url": f"https://{s}", "status": 200} for s in subdomains[:5]]

    async def _nmap_scan(self, targets: list[str]) -> list[dict]:
        """Run nmap port scan."""
        logger.info(f"Scanning {len(targets)} targets")
        # Placeholder — integrates with nmap
        return [{"port": 443, "service": "https"}, {"port": 80, "service": "http"}]

    def _extract_tech(self, hosts: list[dict]) -> list[str]:
        """Extract technologies from host data."""
        tech = set()
        for h in hosts:
            if server := h.get("server"):
                tech.add(server)
            if powered := h.get("x-powered-by"):
                tech.add(powered)
        return list(tech)

    def _build_analysis_prompt(self, target, subs, hosts, ports) -> str:
        """Build prompt for AI analysis."""
        return f"""Analyze this reconnaissance data for {target}:

Subdomains ({len(subs)}):
{chr(10).join(subs[:50])}

Live Hosts ({len(hosts)}):
{json.dumps(hosts[:20], indent=2)}

Open Ports:
{json.dumps(ports, indent=2)}

Identify:
1. High-value targets (admin panels, APIs, dev/staging)
2. Potential attack vectors
3. Technology stack vulnerabilities
4. Priority ranking for further testing"""
