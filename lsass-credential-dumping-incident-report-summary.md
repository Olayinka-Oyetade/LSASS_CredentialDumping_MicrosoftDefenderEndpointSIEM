# Incident Report: Confirmed Credential Theft

## Initial Triage

An alert came in flagged as possible human-operated activity on a Windows server. The first thing in the chain was a clean Windows boot process, the kind of thing that tempts a junior analyst to clear the ticket and move on. I did the opposite. A benign process showing up inside a flagged incident is a question, not an answer, so I asked what else Defender had correlated into it.

## The Real Lead

That instinct led to the real lead. An unsigned binary called Outflank-Dumpert, flagged 52 out of 70 on VirusTotal, had reached into the memory of LSASS, the part of Windows that holds every cached credential on the machine. I traced how it arrived: a PowerShell download cradle pulled it from a public code-hosting site, then cmd.exe launched it. Classic stage and execute.

## Impact Assessment

The question that actually matters in a credential theft is whether the attacker got anything. I refused to assume. I hunted for the dump file and found it on disk at 53 megabytes, the size of a full memory image. That single fact turned the incident from suspicious into contain now.

## Closing the Investigation

Then I finished the job. I cleared a benign browser artifact that correlation had swept in, confirmed through a network hunt that the dump never left the host, mapped every move to MITRE ATT&CK, and wrote the containment and recovery plan. Defender detected the technique and isolated the host on its own. I proved the coverage held, and I produced reusable detections so the next analyst catches it faster.

## Verdict

Confirmed true positive.
