# LSASS Credential Dumping: Detection Validation & Incident Investigation

### MITRE ATT&CK T1003.001 · Microsoft Defender for Endpoint · KQL Threat Hunting · Atomic Red Team

> I emulated a realistic credential-theft attack chain on a live Windows Server, validated that Microsoft Defender for Endpoint detected it, then ran the complete SOC investigation a Tier 1 analyst performs to confirm the intrusion, scope the impact, enrich with threat intelligence, and recommend containment. End to end, attacker to verdict.

![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-T1003.001-red)
![Microsoft Defender for Endpoint](https://img.shields.io/badge/EDR-Microsoft_Defender_for_Endpoint-0078D4)
![KQL](https://img.shields.io/badge/Threat_Hunting-KQL_Advanced_Hunting-512BD4)
![Atomic Red Team](https://img.shields.io/badge/Emulation-Atomic_Red_Team-orange)
![Verdict](https://img.shields.io/badge/Verdict-Confirmed_True_Positive-success)

---

## TL;DR

A credential-dumping tool was downloaded through a PowerShell cradle, executed via `cmd.exe`, and successfully dumped the memory of Windows LSASS to disk. I caught it, proved the dump succeeded using endpoint telemetry rather than assumption, reconstructed the full attack lifecycle, ruled out exfiltration, and wrote the containment plan. Microsoft Defender for Endpoint detected the technique and auto-isolated the host. Detection coverage validated. Verdict confirmed.

This is not a tutorial walkthrough. It is the investigation, written the way an analyst reasons through a live incident.

---

## Why This Technique Matters

LSASS credential dumping is one of the most common and most damaging steps in modern intrusions. It is a recurring precursor in ransomware operations, because a single successful dump can hand an attacker every credential cached on a machine and unlock pass-the-hash and lateral movement across an entire domain. Validating that an EDR detects this technique, and that analysts can investigate it confidently, is exactly the capability that shrinks attacker dwell time and stops one compromised host from becoming a domain-wide breach.

---

## The Attack Chain

I deliberately chose **Outflank-Dumpert**, an evasion-aware dumper that uses direct system calls and API unhooking to avoid the userland hooks many EDRs rely on. Validating detection against an evasion tool is a far stronger test than a naive `procdump` run.

```
powershell.exe        Download cradle: TLS 1.2, stage directory, Invoke-WebRequest
   └── cmd.exe         /c launch the downloaded binary
        └── Outflank-Dumpert.exe   Unsigned · VirusTotal 52/70
             └── accessed lsass.exe   →  dumpert.dmp written (53 MB)
```

After the dump, the operator ran `whoami` and `hostname`, the hands-on-keyboard discovery pattern of a human orienting after gaining access.

---

## What I Proved

| | Result |
|---|---|
| **Detection validated** | MDE fired high-severity Credential Access and Lateral Movement alerts, an explicit T1003.001 alert, and auto-isolated the host through Attack Disruption |
| **Impact confirmed with evidence** | A 53 MB LSASS dump on disk, proven through file-creation telemetry. The difference between "a tool ran" and "credentials were stolen" |
| **Full lifecycle reconstructed** | Execution to credential access to discovery, rebuilt from process-tree analysis and KQL hunting across four telemetry tables |
| **Signal separated from noise** | Identified a benign Edge `Local State` rename pulled in by correlation, verified it, and refocused on the real lead instead of chasing it |
| **Exfiltration ruled out** | Network hunt confirmed no outbound connection from the dumper. The credential dump stayed local at time of detection |
| **Threat intel in context** | VirusTotal results on both the malicious binary and outbound domains interpreted against ownership, timing, and purpose, not on score alone |
| **Reusable detections produced** | Three tuned KQL analytics with explicit false-positive considerations, ready to promote to scheduled detections |
| **Verdict** | Confirmed True Positive, with a full containment, eradication, and recovery plan |

---

## Skills Demonstrated

| Capability | Evidence in this investigation |
|---|---|
| Alert triage and prioritisation | Distinguished a genuine high-severity credential-access alert from benign correlated noise |
| EDR / MDE operation | Process-tree analysis, device timeline review, incident correlation, Attack Disruption handling |
| Threat hunting with KQL | Authored and tuned Advanced Hunting queries across `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceNetworkEvents`, `DeviceEvents` |
| MITRE ATT&CK fluency | Mapped every stage of the attack to ATT&CK tactics and techniques |
| Threat intelligence enrichment | VirusTotal reputation analysis of the malicious binary and outbound domains, interpreted in context |
| Impact analysis | Confirmed credential-dump success through file-creation telemetry and artifact size |
| Detection engineering | Reusable detection logic with false-positive tuning notes |
| Incident reporting | Clear for non-technical stakeholders, rigorous for technical reviewers |

---

## Detection Coverage Results

| Detection layer | Fired in this exercise? |
|---|---|
| MDE built-in: T1003.001 LSASS Memory alert | Yes |
| MDE built-in: Compromised account / hands-on-keyboard | Yes |
| MDE Attack Disruption (automatic host isolation) | Yes |
| Custom analytic: LSASS access by non-system process | Validated against telemetry |
| Custom analytic: suspicious dump artifact in temp path | Validated against telemetry |

---

## What's in This Repo

**[Full Investigation Report →](./T1003_001_LSASS_Credential_Dumping_Investigation.md)**

The complete write-up: executive summary, lab environment, attack narrative, the step-by-step investigation walkthrough with analyst reasoning, MITRE ATT&CK mapping, indicators of compromise, the detection-engineering queries, findings, and the recommended response plan.

---

## Tech Stack & Environment

| | |
|---|---|
| **Host** | Windows Server 2025 Datacenter, Azure-hosted |
| **EDR** | Microsoft Defender for Endpoint (fully onboarded) |
| **Investigation** | Microsoft Defender XDR portal + Advanced Hunting (KQL) |
| **Emulation** | Atomic Red Team |
| **Framework** | MITRE ATT&CK |
| **Threat intel** | VirusTotal |

This was a controlled detection-validation exercise in an isolated lab I own and operate. No production systems, third-party data, or unauthorised targets were involved.

---

## About

**Olayinka Oyetade** — Security Operations / Detection Engineering.

I build hands-on detection labs that emulate real attacker tradecraft and then investigate them the way a SOC does. This repo is one of a series of MITRE ATT&CK-mapped detection-engineering investigations across Microsoft Defender for Endpoint, Microsoft Sentinel, and Splunk.

- Portfolio: [olayinkaoyetade.com](https://olayinkaoyetade.com)
- GitHub: [github.com/olayinkaoyetade](https://github.com/olayinkaoyetade)
- LinkedIn: _add your profile URL here_
