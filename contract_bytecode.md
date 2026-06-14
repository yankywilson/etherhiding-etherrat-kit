# On-Chain Resolver — Decompilation & Reproduction Queries

**Report:** CTI-2026-0614-ETHERHIDING-KIT — supporting technical annex
**TLP:CLEAR**

This annex documents the resolver contract internals and provides the exact public queries to reproduce the on-chain findings independently. No privileged access is required.

---

## 1. Resolver contract — decompiled logic

The deployed runtime bytecode resolves to a minimal two-function EtherHiding resolver. Decoded behavior:

| Selector | Signature | Behavior |
|---|---|---|
| `0x7fcaf666` | `setString(string newString)` | Writes `mapping[msg.sender] = newString`; emits `StringChanged(msg.sender, newString)` |
| `0x7d434425` | `getString(address account)` | Returns `mapping[account]` (the stored C2 string) |

**Event:** `StringChanged(address indexed account, string newString)`
**topic0:** `0x3ca6280dac32fee85e9d3d81188d59eed7e4966e5b3df13a910924cf6ade2d47`
**Compiler:** Solidity `0.8.30`

### Why this matters analytically

Storage is keyed on `msg.sender` (`mapping(address => string)`). Each operator's C2 is namespaced under that operator's wallet. A reader calls `getString(operatorAddress)` to fetch a specific operator's current C2. This is the technical proof of the **per-operator fan-out / builder-kit** model: one contract instance can serve many operators, and the kit ships the contract so operators can also deploy their own byte-identical copies (hence the 24 byte-identical instances).

### Reads generate no transaction

C2 lookups are `eth_call` (a read), not a transaction. They never appear in `ethereum.transactions` and produce no on-chain trace. This is why endpoint-side detection of *RPC egress* matters more than chain monitoring for catching a victim, and why the resolver cannot be "taken down."

---

## 2. Reproduction — Dune Analytics

Discover the contract family by the family event topic0:

```sql
-- Family discovery: every contract emitting the resolver event
SELECT contract_address,
       COUNT(*)        AS rotations,
       MIN(block_time) AS first_seen,
       MAX(block_time) AS last_seen
FROM ethereum.logs
WHERE topic0 = 0x3ca6280dac32fee85e9d3d81188d59eed7e4966e5b3df13a910924cf6ade2d47
GROUP BY 1
ORDER BY rotations DESC;
```

Bytecode-dedupe to separate byte-identical from variant instances:

```sql
SELECT to_hex(sha256(code)) AS code_hash,
       COUNT(*)             AS instances,
       MIN(block_time)      AS first_deploy
FROM ethereum.creation_traces
WHERE position('3ca6280dac32fee85e9d3d81188d59eed7e4966e5b3df13a910924cf6ade2d47'
               IN lower(to_hex(code))) > 0
GROUP BY 1
ORDER BY instances DESC;
```

Cluster operator wallets (deployers):

```sql
SELECT "from" AS operator_wallet,
       COUNT(*) AS deploys
FROM ethereum.creation_traces
WHERE position('3ca6280dac32fee85e9d3d81188d59eed7e4966e5b3df13a910924cf6ade2d47'
               IN lower(to_hex(code))) > 0
GROUP BY 1
ORDER BY deploys DESC;
```

> **Note on string search in `ethereum.logs`:** the C2 string in a `StringChanged` event is ABI-encoded (length-prefixed) and stored with the `https://` prefix as the operator wrote it. A naive `position()` match on a bare IP/host hex may miss it. The reliable way to read the **current** C2 values is the next method (Etherscan events), which decodes the string for you.

---

## 3. Reproduction — Etherscan (decoded, no SQL)

For any resolver instance, open the contract's **Events** tab and read decoded `StringChanged` values directly:

```
https://etherscan.io/address/0x45729d7424d7310a0c041a2906ba95a4bd5ebfca#events
```

Each event row shows `Method 0x7fcaf666` (`setString`), the emitting `account` (operator wallet), and the decoded `newString` (the C2, in cleartext). This is the fastest way to recover the current C2 for an operator and to confirm an instance belongs to the family (selector + topic0 will match).

---

## 4. Reproduction — panel enumeration (Censys)

```
host.autonomous_system.asn: 206134 and host.services.http.response.headers.value: "X-Bot-Server"
```

Use the `X-Bot-Server` header as the discriminator. Do **not** rely on the ETag or the ASN alone (false-positive prone — see README §3.3).

---

## 5. Reproduction — hijacked-domain proof (passive DNS)

SecurityTrails (or equivalent) historical A-record / IP history for `aravisblog.com` shows continuous Automattic/Rackspace/AWS hosting 2010→2026, then a repoint to `31.76.16.211` (OOO Razvitie, RU) on 2026-06-08. The abrupt ASN/age-profile change on a 16-year domain is the takeover signature.

---

## 6. Reproduction — family corroboration (ThreatFox)

```
https://threatfox.abuse.ch/browse/malware/EtherRAT/
```

Cross-reference the on-chain-recovered C2 against the `malware:EtherRAT` set. Multiple endpoints (e.g. `rubysen.com`, `ager-stp.org`) appear in both, reported independently.
