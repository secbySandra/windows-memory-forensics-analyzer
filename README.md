# Windows Memory Forensics Analyzer

## Overview

This project demonstrates an automated Windows memory forensic analysis pipeline implemented in Bash.

The tool performs:

- File carving (foremost, binwalk, bulk_extractor, strings)
- PCAP detection
- Volatility memory analysis (process, registry, network artifacts)
- Process dumping and hash generation
- Structured reporting and artifact packaging

The goal is to simulate a structured DFIR (Digital Forensics & Incident Response) workflow in a controlled lab environment.

---

## Technical Stack

- Bash
- Foremost
- Binwalk
- Bulk Extractor
- Strings
- Volatility 2.6
- Linux (Kali)

---

## Workflow

1. Root & dependency validation
2. Target file verification
3. Artifact carving
4. PCAP detection
5. Volatility memory analysis
6. Artifact triage & process dumping
7. Report generation
8. ZIP packaging

---

## Example Findings (Memory Dump Analysis)

- Windows XP memory profile detected
- Multiple active system processes identified
- Network connections discovered (TCP/UDP)
- PCAP artifact recovered
- 3000+ artifacts extracted
- Process dumps generated and hashed

---

## How to Run

```bash
chmod +x nx212_analyzer.sh
sudo ./nx212_analyzer.sh
```

---

## Disclaimer

This project was developed and executed in a controlled lab environment for educational purposes only.
