# Architecture Guide

## Overview

OmniSec AI uses a multi-model AI orchestration pattern where different AI models handle different phases of security testing based on their strengths.

## Core Components

### 1. AI Orchestrator (`src/core/orchestrator.py`)

The brain of the system. Routes tasks to optimal AI models:

```
Task Type → Model Selection → API Call → Response Parsing
```

**Routing Matrix:**
- Recon Analysis → MiMo V2.5 (fast reasoning)
- Vulnerability Detection → Claude (detailed analysis)
- Exploit Development → Claude (code generation)
- Report Generation → Claude/GPT-4 (natural language)
- Image Analysis → Gemini (multimodal)

### 2. Engine (`src/core/engine.py`)

Runs the full pipeline:

```
Phase 1: Reconnaissance
  └→ Subdomain enum → Live host detection → Port scanning
  └→ AI interprets results, identifies attack surface

Phase 2: Vulnerability Analysis
  └→ Nuclei scan → AI false positive reduction → CVSS scoring
  └→ AI suggests exploitation paths

Phase 3: Report Generation
  └→ AI generates professional report with findings
```

### 3. Modules (`src/modules/`)

Pluggable modules for specific tasks:
- `recon.py` — Subdomain, port, tech stack discovery
- `vuln_scanner.py` — Vulnerability detection with AI analysis
- `report_gen.py` — Professional report generation

## Data Flow

```
Target URL
    ↓
[Recon Module] → Subdomains, hosts, ports
    ↓
[AI Orchestrator] → Analysis & prioritization
    ↓
[Vuln Scanner] → Nuclei + AI interpretation
    ↓
[AI Orchestrator] → False positive reduction
    ↓
[Report Generator] → AI-generated report
    ↓
Output (Markdown/HTML/JSON)
```

## Multi-Model Strategy

Each AI model is chosen for its strength:

| Model | Strength | Used For |
|-------|----------|----------|
| MiMo V2.5 | Fast reasoning | Recon analysis, prioritization |
| Claude | Code & security | Vuln detection, exploit dev |
| GPT-4o | General purpose | Report generation, fallback |
| Gemini | Multimodal | Screenshot analysis, APK |

## Error Handling

- Automatic model fallback (if Claude fails → try GPT-4 → try MiMo)
- Graceful degradation (partial results better than none)
- All API calls have timeout + retry logic
