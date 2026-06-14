# Disclaimer & Usage

**TLP:CLEAR.** This repository is published for defensive purposes — detection,
hunting, and situational awareness for SOC and CTI teams.

- All indicators are derived from **passive OSINT** against public sources
  (Etherscan, Dune, Censys, Shodan, VirusTotal public tabs, abuse.ch
  ThreatFox/MalwareBazaar, SecurityTrails, public sandbox reports), with two
  active touches disclosed in the main README (§8).
- Indicators carry **per-indicator confidence**. Tier your response accordingly.
  The on-chain resolver design means C2 endpoints **rotate by design** —
  prioritize the behavioral, fingerprint, and on-chain-family detections over
  static C2 strings.
- **Attribution is bounded.** The family label (EtherRAT) is high confidence;
  operator/nation attribution is **not made** here (README §7).
- Detection content is provided as-is. **Validate in your environment before
  enforcing blocks**, especially the Ethereum-RPC network rules, which can false
  positive on legitimate developer/wallet hosts.
- This is independent research and is **not** legal advice or a vendor product.

Issues, corrections, and additional corroborating telemetry are welcome.

_License: detection content (YARA/Sigma/Suricata/KQL) released under
permissive terms for operational use; cite the report ID where practical._
