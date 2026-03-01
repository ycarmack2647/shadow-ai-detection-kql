# Shadow AI Detection KQL Pack

> **Microsoft Sentinel + MDE detection queries for identifying unauthorized AI tool usage across enterprise environments**

Built by a Cloud Security Engineer at a regulated transit agency to address the growing risk of employees using consumer AI tools (ChatGPT, Claude, Gemini, local LLMs) with sensitive organizational data — with zero visibility to the security team.

---

## The Problem

Employees are using AI tools. Security teams can't see it.

- 80%+ of Fortune 500 companies have active AI agents in use (Microsoft, 2026)
- Consumer AI tools (ChatGPT, Gemini, Claude) have no enterprise DLP controls
- Local LLMs (Ollama, LM Studio) generate **zero network traffic** — invisible to standard monitoring
- Traditional DLP catches data *at the destination* — this pack catches the *behavior pattern* before data leaves

---

## Detection Coverage

| # | Detection | Tables Used | MITRE Technique | Severity |
|---|---|---|---|---|
| 01 | [AI Domain Traffic](detections/01_ai_domain_traffic.kql) | `DeviceNetworkEvents` | T1567, T1071.001 | Medium |
| 02 | [Large Data Uploads to AI](detections/02_large_data_upload_to_ai.kql) | `DeviceNetworkEvents` | T1567.002, T1048 | High |
| 03 | [Sensitive File Access → AI Traffic](detections/03_sensitive_file_access_before_ai_traffic.kql) | `DeviceFileEvents` + `DeviceNetworkEvents` | T1213, T1530 | High |
| 04 | [Shadow AI App Download/Install](detections/04_shadow_ai_app_download.kql) | `DeviceFileEvents` + `DeviceProcessEvents` | T1072, T1176 | Medium |
| 05 | [Scripted / Automated AI API Usage](detections/05_scripted_ai_api_usage.kql) | `DeviceNetworkEvents` + `DeviceProcessEvents` | T1059, T1567.002 | High → Critical |

---

## Requirements

- Microsoft Defender for Endpoint (MDE) — Plan 2
- Microsoft Sentinel (Log Analytics workspace with MDE connector)
- M365 E5 or equivalent licensing
- MDE data connector enabled in Sentinel

> All queries are written against **MDE tables only** — no additional connectors required.

---

## Quick Start

### 1. Run Detection 01 First (Baseline)
Paste `detections/01_ai_domain_traffic.kql` into your Sentinel Log Analytics workspace and run it. This gives you an immediate picture of what AI tools are already in use.

```kql
// Quick version — paste this in Sentinel to get started in 30 seconds
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteUrl has_any (dynamic(["openai.com","claude.ai","gemini.google.com","perplexity.ai","huggingface.co"]))
| summarize Connections = count() by DeviceName, InitiatingProcessAccountName, RemoteUrl
| order by Connections desc
```

### 2. Tune the Sanctioned Domain List
In each query file, find the `Sanctioned_AI_Domains` variable and add your organization's approved AI tools to suppress false positives.

### 3. Deploy as Sentinel Scheduled Analytics Rules
For each detection you want active monitoring on:
1. Go to **Sentinel → Analytics → Create → Scheduled query rule**
2. Paste the KQL from the detection file
3. Set frequency and lookback window as noted in each file's header
4. Configure alert severity and incident creation settings

### 4. Set Up Alerts for High/Critical Detections
Priority alert rules to configure first:
- Detection 02 (Large uploads) → Severity: High, frequency: 30 min
- Detection 05 (Scripted API) → Severity: High, frequency: 30 min

---

## Repo Structure

```
shadow-ai-detection-kql/
│
├── README.md                          ← You are here
│
├── detections/                        ← KQL query files
│   ├── 01_ai_domain_traffic.kql
│   ├── 02_large_data_upload_to_ai.kql
│   ├── 03_sensitive_file_access_before_ai_traffic.kql
│   ├── 04_shadow_ai_app_download.kql
│   └── 05_scripted_ai_api_usage.kql
│
├── reference/
│   └── known_ai_domains.md            ← Maintained domain/IOC list
│
└── docs/
    └── wmata-gap-analysis.md          ← Org-specific gap analysis template
```

---

## AI Services Covered

**Consumer Chat:** ChatGPT, Google Gemini, Claude, Perplexity, Character.AI, Poe, Meta AI

**Developer APIs:** OpenAI API, Anthropic API, Gemini API, Cohere, Mistral, Hugging Face, Groq, Together AI, OpenRouter

**Local LLMs (endpoint-level):** Ollama, LM Studio, GPT4All, Jan.ai — detected via GGUF/GGML model file downloads

**AI Code Tools:** GitHub Copilot, Cursor, Codeium, Tabnine

See [reference/known_ai_domains.md](reference/known_ai_domains.md) for the full list with domains.

---

## Understanding the Detection Logic

### Detection 03 — Why Behavioral Correlation Matters
Standard DLP catches data *at the destination*. Detection 03 catches the *intent* by correlating:
1. User opens a sensitive file (`.csv`, `.pdf`, `.env`, etc.)
2. Within 10 minutes, the same user connects to an AI service

This fires **before** any data upload is detected — earlier in the kill chain.

### Detection 04 — The Local LLM Blind Spot
Local LLMs running on endpoints generate **zero cloud traffic**. They're completely invisible to:
- Firewall logs
- Proxy logs
- Cloud CASB solutions
- Network DLP

Detection 04 catches them by monitoring for GGUF/GGML model file creation events at the endpoint — the only reliable detection surface for this threat.

### Detection 05 — Highest Risk Vector
Browser AI usage = one person, manual, limited volume.
Scripted API usage = automated, potentially millions of records processed, at scale.

A single Python script with a personal OpenAI API key can process an entire HR database in minutes. Detection 05 catches `python.exe`, `powershell.exe`, `curl.exe` and other non-browser processes calling AI APIs.

---

## Contributing

Found a new AI service that should be added? Submit a PR updating `reference/known_ai_domains.md`.

Tuning suggestions welcome — especially org-specific path patterns for Detection 03.

---

## Resources

- [Microsoft 2026 Data Security Index](https://www.microsoft.com/en-us/security/blog/2026/01/29/new-microsoft-data-security-index-report-explores-secure-ai-adoption-to-protect-sensitive-data/)
- [Microsoft Cyber Pulse: AI Security Report](https://www.microsoft.com/en-us/security/security-insider/emerging-trends/cyber-pulse-ai-security-report)
- [MITRE ATT&CK — Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/)
- [MDE Advanced Hunting Schema Reference](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables)

---

*Built for Microsoft Sentinel + MDE | March 2026*  
*Author: Cloud Security Engineer — Transit Sector*
