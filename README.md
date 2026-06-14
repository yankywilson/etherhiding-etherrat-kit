# Distributed EtherHiding Resolver Kit — EtherRAT Family

**Threat Intelligence Assessment & Defender Resource Pack**

| | |
|---|---|
| **Report ID** | CTI-2026-0614-ETHERHIDING-KIT |
| **Date of Assessment** | 2026-06-14 |
| **Classification** | TLP:CLEAR — public, unrestricted distribution |
| **Author** | Independent CTI research (passive OSINT) |
| **Assessment standard** | ICD-203 analytic confidence language applied throughout |
| **Status** | Investigation complete; one analytic dependency carried as inference (documented below) |

---

## How to read this document

This is a finished intelligence product, not a dump of indicators. Each major claim carries an explicit confidence judgment using [ICD-203](https://www.dni.gov/files/documents/ICD/ICD%20203%20Analytic%20Standards.pdf) probability and confidence vocabulary. Where a link in the chain was **observed**, it is labeled as such. Where a link is **inferred**, the inference and its basis are stated plainly rather than smoothed over. The IOC tables carry a per-indicator confidence column so that a defender ingesting them can tier their own response.

Two analyst actions in this investigation crossed a passive-only collection standard. **Both are disclosed in the Methodology section.** Nothing in this report depends on privileged access, a vendor feed, or a paywalled source; every indicator is independently reproducible from the named public sources.

---

## 1. Bottom Line Up Front (BLUF)

A **distributed EtherHiding command-and-control (C2) resolution kit**, aligning to the publicly reported **EtherRAT** malware family, is in active operation as of June 2026. We assess **with high confidence** that:

- The kit uses a **family of byte-identical and near-identical smart contracts on Ethereum mainnet** as a censorship-resistant C2 resolver layer. We identified **24 byte-identical and 9 variant resolver contracts**, materially more than the single contract described in prior public reporting.
- Each operator deploys or writes to their **own contract instance under their own wallet** (a per-operator fan-out design), and publishes their current C2 endpoint **in cleartext** on-chain via a `setString(string)` call. We mapped **~30 operator wallets** and recovered **19+ distinct C2 endpoints** directly from on-chain event data.
- A **server-side operator panel** with a stable, fingerprintable HTTP signature fronts the C2 tier. We enumerated **52 live panels** across NEKO (AS206134), Microsoft Azure, and residential hosting.
- Operators deliver via **both throwaway domains and hijacked aged domains**. We documented one 16-year-old legitimate WordPress blog (`aravisblog.com`) repointed to a kit panel on 2026-06-08, exploiting the domain's clean reputation (1/91 vendor detections at time of analysis).
- A delivered **MSI loader** (`56058b92…`, 0/61 AV) was **observed in sandbox** dropping a Node.js stage, executing it under `conhost --headless`, querying multiple public Ethereum RPC providers, and beaconing to a kit panel — confirming the EtherHiding resolution mechanism on a live sample.

We assess **with moderate confidence** that the family is operated by **multiple distinct actors** rather than a single group, consistent with a *builder kit / malware-as-a-service* model rather than a single intrusion set. **Operator-level attribution is not made** in this report (see Section 7).

---

## 2. What is new here

Defenders and researchers tracking EtherHiding/EtherRAT will find the following net-new relative to prior public reporting:

| Finding | Prior public reporting | This assessment |
|---|---|---|
| Resolver contracts | Generally a single contract | **24 byte-identical + 9 variant** contracts (family) |
| Architecture | Often described as one resolver | **Per-operator fan-out**, `mapping(address => string)`, confirmed at bytecode level |
| Operator wallets | Not enumerated | **~30** clustered wallets |
| C2 endpoints | Limited set | **19+** recovered directly from chain, several previously unpublished |
| Panel fingerprint | Not published | Stable **`X-Bot-Server` CORS + ETag** signature; **52** live panels enumerated |
| Delivery tradecraft | Throwaway domains | **Hijacked aged domains** documented with DNS-history proof |

---

## 3. Technical Analysis

### 3.1 The on-chain resolver (EtherHiding layer)

The C2 location is not hardcoded in the malware. Instead, the malware reads it from a smart contract on Ethereum mainnet — the EtherHiding technique. Because reads are performed as `eth_call` against public RPC providers, the lookups generate no on-chain transaction and are resilient to domain/IP takedown: an operator simply writes a new endpoint with one `setString` call.

**Contract family fingerprint (observed):**

| Element | Value |
|---|---|
| Event signature | `StringChanged(address account, string newString)` |
| Event topic0 | `0x3ca6280dac32fee85e9d3d81188d59eed7e4966e5b3df13a910924cf6ade2d47` |
| Setter selector | `0x7fcaf666` → `setString(string)` |
| Getter selector | `0x7d434425` → `getString(address)` |
| Storage model | `mapping(address => string)` — keyed on `msg.sender` |
| Compiler | Solidity 0.8.30 |

The bytecode was retrieved and decompiled (see [`analysis/contract_bytecode.md`](analysis/contract_bytecode.md)). The setter writes the caller-supplied string to `mapping[msg.sender]` and emits `StringChanged(msg.sender, newString)`. The getter returns `mapping[queriedAddress]`. This design is the technical basis for the per-operator fan-out assessment: **each operator's C2 is namespaced under their own wallet address**, so a single contract instance can serve many operators, and many byte-identical instances exist because the kit ships the contract for operators to deploy themselves.

**Observed live resolver instance:** `0x45729d7424d7310a0c041a2906ba95a4bd5ebfca`

Decoded `StringChanged` events from this instance recovered current C2 in cleartext, including `https://isocell.swedencentral.cloudapp.azure.com`, `https://dmors.com`, and `https://leopriego.com`, written by operator wallet `0xA001D3863b138eD523f255f62725AB1ddc82af87`. These values match endpoints independently corroborated as EtherRAT (Section 5).

### 3.2 The loader and execution chain (observed)

A 30 KB MSI loader (`v9.msi`, SHA-256 `56058b92ce87a8e6a46b1b9a71e2cd0b32325e6a54e26d6e500f3b0b0f05cc0b`, 0/61 vendor detections) was analyzed via public sandbox behavior reporting. The execution chain was **observed**:

```
v9.msi  (msiexec /qb)
  └─ drops node.exe  (masqueraded under \Program Files (x86)\Common Files\Oracle\Java\javapath\
                       and \Program Files\nodejs\)
  └─ drops JS stage  cDQMlQAru0.xml  (Node script, .xml-disguised)
  └─ conhost --headless "node.exe" "...\2PhU26hCp7GZ\cDQMlQAru0.xml"
        └─ JS stage queries public Ethereum RPC providers (eth_call to resolver contract)
        └─ resolves C2  →  beacons to panel  31.76.16.211
  └─ persistence: Run-key autostart (reg.exe)
  └─ anti-analysis: PowerShell VM/sandbox checks, USB-bus check, AV enumeration
```

**RPC providers queried (observed in sandbox network trace):**
`eth-mainnet.public.blastapi.io`, `eth.drpc.org`, `eth.merkle.io`, `ethereum-rpc.publicnode.com`, `mainnet.gateway.tenderly.co`, `rpc.mevblocker.io`, `rpc.flashbots.net`.

Querying multiple RPC providers in parallel and taking a majority/first answer is consistent with the publicly documented EtherRAT resolution behavior. **The EtherHiding mechanism is therefore confirmed on this specific sample** — the loader does resolve C2 via Ethereum RPC and does reach a kit panel.

### 3.3 The operator panel (observed)

The C2 tier presents a consistent HTTP signature. The reliable discriminator is the CORS header advertising a custom `X-Bot-Server` header; the ETag is a secondary marker.

```
HTTP/1.1 404 Not Found
Server: nginx
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, PATCH, OPTIONS
Access-Control-Allow-Headers: Content-Type, Authorization, X-Bot-Server
ETag: W/"9-0gXL1ngzMqISxa6S1zx3F4wtLyg"
```

A Censys header search for the `X-Bot-Server` value enumerated **52 live panels**, clustering on NEKO / NEKOBYTE INTERNATIONAL LTD (AS206134, Frankfurt), with additional hosts on Microsoft Azure and UK residential ranges (suspected relays).

> **Discriminator note for defenders:** the ETag alone is **not** a reliable selector — it is the default Express "Not Found" 9-byte body hash and appears on thousands of unrelated hosts. The ASN alone is **not** a reliable selector either. **Use the `X-Bot-Server` header, or the header intersected with the ASN.** This is documented so that defenders do not generate false positives from the weaker markers.

### 3.4 Delivery: hijacked aged domains (observed)

Operators were observed using a 16-year-old legitimate WordPress/Automattic blog, `aravisblog.com`, as a delivery/panel front. Passive DNS history shows the domain hosted on Automattic/Rackspace/AWS infrastructure continuously from 2010 through early 2026, then repointed to the kit panel `31.76.16.211` (OOO Razvitie Optimizatsiya, RU) on **2026-06-08**. At time of analysis the domain carried **1/91** vendor detections — its aged reputation actively shields the infrastructure.

The takeover additionally published non-standard DNS service-locator records — `_3389._https.aravisblog.com` and `_3300._https.aravisblog.com` — indicating remote-access/panel service wiring beyond simple web hosting. These are included as IOCs.

---

## 4. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Resource Development | Acquire Infrastructure: Domains (hijacked aged) | T1583.001 | `aravisblog.com` takeover |
| Initial Access | Replication Through Removable Media (USB check) | T1091 | Sandbox behavior tag |
| Execution | Command and Scripting Interpreter: JavaScript (Node) | T1059.007 | `node.exe cDQMlQAru0.xml` |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | Hidden PS recon commands |
| Defense Evasion | Indirect Command Execution (`conhost --headless`) | T1202 | Process tree |
| Defense Evasion | Masquerading (node.exe under Oracle\Java path) | T1036.005 | Dropped file path |
| Defense Evasion | Virtualization/Sandbox Evasion | T1497 | PS VM checks |
| Persistence | Boot or Logon Autostart: Run Keys | T1547.001 | `reg.exe` Run-key write |
| Command and Control | Application Layer Protocol: Web (resolver) | T1071.001 | RPC `eth_call` + HTTPS beacon |
| Command and Control | **Encrypted/obfuscated C2 resolution via blockchain (EtherHiding)** | T1102 / T1568 | On-chain resolver |

---

## 5. Independent Corroboration

This assessment was reached by three methods that were applied independently and then found to agree:

1. **On-chain analysis** — recovered the C2 set directly from `StringChanged` events.
2. **Host fingerprinting** — enumerated panels via the `X-Bot-Server` HTTP signature.
3. **Community attribution (ThreatFox)** — the public abuse.ch ThreatFox dataset independently tags multiple of the on-chain-recovered endpoints (e.g. `rubysen.com`, `ager-stp.org`, `issueall.com`, `webiqonline.com`, `dakindsoups.com`, and Azure/Cloudflare-tunnel endpoints) as **EtherRAT**, reported by an unrelated researcher.

The convergence of three independent methods on the **same family** and the **same infrastructure** is the basis for the high-confidence family assessment.

---

## 6. Confidence Scorecard

| Analytic claim | Status | Confidence |
|---|---|---|
| 24+9 resolver contract family + ~30 wallets | Observed (on-chain) | **High** |
| Contract is the EtherHiding resolver kit (per-operator fan-out) | Observed (bytecode decompiled) | **High** |
| C2 published in cleartext on-chain; 19+ endpoints recovered | Observed (decoded events) | **High** |
| Panel HTTP fingerprint; 52 live panels | Observed (Censys + packet) | **High** |
| Hijacked aged domain → panel | Observed (DNS history + packet) | **High** |
| Family = EtherRAT; on-chain C2 ∈ EtherRAT set | Corroborated (ThreatFox, independent) | **High** |
| Loader resolves C2 via Ethereum RPC → panel | Observed (sandbox behavior) | **High** |
| **The specific contract instance read by a given loader run** | **Inferred** | **Moderate–High** |
| Multiple distinct operators (kit/MaaS model) | Assessed (architecture implies) | **Moderate** |
| Operator-level attribution | **Not made** | — |

### The one inference, stated plainly

The loader resolves C2 via **TLS-encrypted** `eth_call` to public RPC providers. The sandbox trace therefore proves the loader *uses* the EtherHiding mechanism and *reaches a kit panel*, but does **not** directly reveal *which* contract address the loader queried. We assess **with moderate-to-high confidence** that the contract read is a member of the documented 24+9 family, on the basis that: (a) the resolved C2 matches the on-chain-recovered set, (b) the destination panel carries the kit fingerprint, and (c) the family is the only known infrastructure producing that C2/panel combination. A defender or researcher wishing to eliminate this inference can extract the address from the dropped JS stage (`cDQMlQAru0.xml`, SHA-256 `bbc4150d…`) via static analysis.

---

## 7. Attribution — deliberately bounded

The **EtherRAT family** is publicly associated in open reporting with North Korea-nexus activity (e.g. Contagious Interview tradecraft) and has been linked to the React2Shell vulnerability class. That association is reported here as **context for the family**, not as a finding of this investigation.

We **do not** attribute this activity to a specific named group, and defenders should not infer one from this report. The reasons are methodological:

- The architecture is a **distributed, per-operator kit**. A shared resolver family used by many operators is the *opposite* of an attribution signal — it pools unrelated actors under one fingerprint.
- Russian hosting (OOO Razvitie, NEKO/AS206134) is **infrastructure procurement**, not nationality.
- Single-source or single-vendor attribution is capped at MODERATE by our standard, and nothing here rises even to that for a *specific operator*.

Treat the family label (EtherRAT) as **high confidence** and any operator/nation label as **uncommitted**.

---

## 8. Methodology & Source Disclosure

**Collection posture:** passive OSINT throughout, against an air-gapped analysis standard. Sources: Etherscan, Dune Analytics (`ethereum.logs`), Censys, Shodan, VirusTotal (public relations/behavior tabs), abuse.ch ThreatFox and MalwareBazaar, SecurityTrails (passive DNS/IP history), public sandbox behavior reports.

**Disclosed active touches (2):** this investigation included two actions that contacted live infrastructure and are disclosed for analytic honesty:

1. One **cloud-sandbox detonation** of `aravisblog.com` (2026-06-14), which produced the panel HTTP capture.
2. One **manual liveness check** of `31.76.16.211` via a third-party HTTP request service.

Neither action used analyst-controlled infrastructure to contact suspected C2 directly, and no active contact was made with the Ethereum contracts beyond standard public RPC reads. **No claim in this report depends on a privileged feed; every indicator is reproducible from the public sources named above.**

**Reproduction queries** are provided in [`analysis/contract_bytecode.md`](analysis/contract_bytecode.md) and inline in the detection files.

---

## 9. Repository Contents

| Path | Contents |
|---|---|
| `README.md` | This intelligence briefing |
| [`IOCs/indicators.csv`](IOCs/indicators.csv) | Master IOC table, per-indicator confidence + context |
| [`IOCs/contracts.csv`](IOCs/contracts.csv) | On-chain contracts and operator wallets |
| [`detections/etherrat_loader.yar`](detections/etherrat_loader.yar) | YARA — loader/JS stage |
| [`detections/etherrat_behavior.yml`](detections/etherrat_behavior.yml) | Sigma — execution-chain behavior |
| [`detections/etherrat_network.rules`](detections/etherrat_network.rules) | Suricata — panel + RPC patterns |
| [`detections/etherrat_hunt.kql`](detections/etherrat_hunt.kql) | KQL — Defender/Sentinel hunt pack |
| [`analysis/contract_bytecode.md`](analysis/contract_bytecode.md) | Decompiled resolver + reproduction queries |

---

## 10. Defensive Recommendations

**Detection (network):**
- Alert on internal hosts performing `eth_call`-pattern HTTPS to multiple public Ethereum RPC providers (`blastapi.io`, `drpc.org`, `merkle.io`, `publicnode.com`, `tenderly.co`, `mevblocker.io`, `flashbots.net`) **outside of known developer/wallet activity**. For most enterprises, endpoints talking to Ethereum RPC is anomalous and high-signal.
- Hunt for the panel fingerprint (`X-Bot-Server` CORS header) on egress.

**Detection (endpoint):**
- `conhost.exe --headless` spawning `node.exe` or `cmd.exe` from a user-writable path is high-signal (see Sigma).
- `node.exe` running a `.xml` argument file, or `node.exe` located under `Oracle\Java\javapath\`, is anomalous.
- New Run-key autostart entries pointing to randomly named binaries in `%APPDATA%\Local\<random>\`.

**Hardening:**
- Block/scope outbound access to public Ethereum RPC providers for non-developer endpoints.
- Treat aged-domain reputation as a **necessary-not-sufficient** signal; a clean 10+ year domain repointed within days is itself suspicious. Where available, alert on large changes in a domain's hosting ASN/age profile.

**Response:**
- The on-chain resolver cannot be taken down. Containment focuses on the **endpoint** (loader, persistence, Node stage) and the **panel/RPC egress**, not the contract.

---

*This product applies ICD-203 analytic standards. Confidence judgments reflect source quality and corroboration as of the assessment date. Indicators may age; the on-chain resolver design means C2 endpoints rotate by design — prioritize the behavioral and fingerprint detections over static C2 strings.*
