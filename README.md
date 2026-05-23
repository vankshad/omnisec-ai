# 🛡️ OmniSec AI — Autonomous Security Testing Framework

> AI-Powered Penetration Testing Automation using Multi-Model Orchestration

[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## Overview

**OmniSec AI** is an autonomous security testing framework that leverages multiple AI models (Claude, GPT-4, Gemini, MiMo) to automate penetration testing workflows — from reconnaissance to exploitation to reporting.

Built with **Hermes Agent** + **Claude Code** + **MiMo API** as the core AI backbone.

## Why This Project?

Traditional pentesting is manual, time-consuming, and requires deep expertise. OmniSec AI uses multi-model AI orchestration to:

- **Automate 80%** of repetitive security testing tasks
- **Chain AI models** for different phases (recon → analysis → exploit → report)
- **Generate professional reports** with AI-powered findings analysis
- **Reduce pentest time** from days to hours

## Architecture

```
┌─────────────────────────────────────────────────┐
│                  OmniSec AI                      │
├─────────────────────────────────────────────────┤
│  ┌──────────┐  ┌──────────┐  ┌──────────┐      │
│  │ Recon    │  │ Analysis │  │ Exploit  │      │
│  │ Module   │→ │ Engine   │→ │ Module   │      │
│  └──────────┘  └──────────┘  └──────────┘      │
│       ↓              ↓             ↓            │
│  ┌──────────────────────────────────────┐       │
│  │     AI Model Orchestrator            │       │
│  │  ┌────────┐ ┌──────┐ ┌────────┐     │       │
│  │  │ Claude │ │ GPT-4│ │  MiMo  │     │       │
│  │  └────────┘ └──────┘ └────────┘     │       │
│  └──────────────────────────────────────┘       │
│                      ↓                          │
│  ┌──────────────────────────────────────┐       │
│  │         Report Generator             │       │
│  └──────────────────────────────────────┘       │
└─────────────────────────────────────────────────┘
```

## Quick Start

```bash
# Install
pip install -r requirements.txt

# Configure
cp config/example.env config/.env
# Edit .env with your API keys

# Run
python -m omnisec --target example.com --mode full
```

## AI Models Used

| Model | Role | Usage |
|-------|------|-------|
| Claude 3.5 Sonnet | Code analysis, exploit dev | Heavy |
| GPT-4o | Recon interpretation | Medium |
| MiMo V2.5 | Reasoning, vulnerability analysis | Heavy |
| Gemini Pro | Image/document analysis | Light |

## Features

- 🔄 Multi-model AI orchestration
- 🔍 Automated subdomain enumeration + analysis
- 🕸️ Web vulnerability scanning with AI interpretation
- 📊 Smart report generation
- 🎯 Target prioritization via AI scoring
- 🔐 API security testing
- 📱 Mobile app analysis (APK)

## Documentation

- [Architecture Guide](docs/architecture.md)
- [API Reference](docs/api-reference.md)
- [Configuration](docs/configuration.md)
- [Examples](examples/)

## License

MIT License — See [LICENSE](LICENSE)

---

**Built with ❤️ using Claude Code, Hermes Agent, and Xiaomi MiMo**
