"""
Vulnerability Scanner — AI-powered vuln detection

Integrates: nuclei, nikto, sqlmap
AI role: Interpret scan results, reduce false positives, suggest exploits
"""

import asyncio
import json
import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class Vulnerability:
    name: str
    severity: str  # critical, high, medium, low, info
    cvss: float
    url: str
    description: str
    evidence: str
    remediation: str
    ai_confidence: float


class VulnScanner:
    """AI-enhanced vulnerability scanner."""

    def __init__(self, orchestrator):
        self.orchestrator = orchestrator

    async def scan(self, targets: list[str], scan_type: str = "full") -> list[Vulnerability]:
        """Run vulnerability scan with AI analysis."""
        logger.info(f"Scanning {len(targets)} targets (type={scan_type})")

        # Step 1: Run nuclei templates
        nuclei_results = await self._run_nuclei(targets)

        # Step 2: AI-powered analysis & false positive reduction
        from ..core.orchestrator import TaskType
        ai_response = await self.orchestrator.route_task(
            TaskType.VULN_DETECTION,
            self._build_vuln_prompt(nuclei_results),
            context={"targets": targets, "scan_type": scan_type},
        )

        # Step 3: Parse AI findings
        vulns = self._parse_findings(ai_response, nuclei_results)

        logger.info(f"Found {len(vulns)} vulnerabilities")
        return vulns

    async def _run_nuclei(self, targets: list[str]) -> list[dict]:
        """Run nuclei vulnerability scanner."""
        try:
            target_input = "\n".join(targets)
            proc = await asyncio.create_subprocess_exec(
                "nuclei", "-silent", "-json", "-",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate(input=target_input.encode())
            results = []
            for line in stdout.decode().strip().split("\n"):
                if line:
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            return results
        except FileNotFoundError:
            logger.warning("nuclei not installed, using mock data")
            return [
                {"template": "xss-detect", "severity": "medium", "host": targets[0] if targets else ""},
                {"template": "info-disclosure", "severity": "low", "host": targets[0] if targets else ""},
            ]

    def _build_vuln_prompt(self, nuclei_results: list[dict]) -> str:
        """Build prompt for AI vulnerability analysis."""
        return f"""Analyze these vulnerability scan results and:

1. Validate each finding (reduce false positives)
2. Assign accurate CVSS scores
3. Provide specific remediation steps
4. Suggest proof-of-concept if applicable

Scan Results:
{json.dumps(nuclei_results[:50], indent=2)}

Output format: JSON array of vulnerabilities with fields:
- name, severity, cvss, url, description, evidence, remediation, confidence"""

    def _parse_findings(self, ai_response, nuclei_results: list[dict]) -> list[Vulnerability]:
        """Parse AI analysis into Vulnerability objects."""
        vulns = []
        try:
            # Try to parse JSON from AI response
            content = ai_response.content
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]

            findings = json.loads(content.strip())
            for f in findings:
                vulns.append(Vulnerability(
                    name=f.get("name", "Unknown"),
                    severity=f.get("severity", "info"),
                    cvss=float(f.get("cvss", 0.0)),
                    url=f.get("url", ""),
                    description=f.get("description", ""),
                    evidence=f.get("evidence", ""),
                    remediation=f.get("remediation", ""),
                    ai_confidence=float(f.get("confidence", 0.5)),
                ))
        except (json.JSONDecodeError, IndexError):
            # Fallback: create generic findings from nuclei data
            for nr in nuclei_results:
                vulns.append(Vulnerability(
                    name=nr.get("template", "Unknown"),
                    severity=nr.get("severity", "info"),
                    cvss=0.0,
                    url=nr.get("host", ""),
                    description=nr.get("template-id", ""),
                    evidence="",
                    remediation="Review manually",
                    ai_confidence=0.3,
                ))
        return vulns
