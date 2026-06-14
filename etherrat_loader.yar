/*
   YARA — Distributed EtherHiding Resolver Kit (EtherRAT family)
   Report: CTI-2026-0614-ETHERHIDING-KIT
   TLP:CLEAR

   NOTE ON CONFIDENCE:
   - rule etherrat_loader_msi_hash and etherrat_resolver_script_hash are
     EXACT hash anchors (highest precision, zero false positives, but brittle
     to recompilation).
   - rule etherrat_node_resolver_heuristic targets the EtherHiding resolution
     behavior (Ethereum RPC provider set + on-chain getter pattern). The RPC
     provider strings were observed in the sandbox NETWORK trace; treat this
     rule as BEHAVIORAL/HEURISTIC for hunting, not as a confirmed-string
     signature, and validate matches before action.
*/

rule etherrat_loader_msi_hash
{
    meta:
        description = "EtherHiding kit loader v9.msi (exact hash anchor)"
        family = "EtherRAT"
        confidence = "high"
        reference = "CTI-2026-0614-ETHERHIDING-KIT"
        hash = "56058b92ce87a8e6a46b1b9a71e2cd0b32325e6a54e26d6e500f3b0b0f05cc0b"
    condition:
        hash.sha256(0, filesize) == "56058b92ce87a8e6a46b1b9a71e2cd0b32325e6a54e26d6e500f3b0b0f05cc0b"
}

rule etherrat_resolver_script_hash
{
    meta:
        description = "EtherHiding kit Node.js C2 resolver stage (exact hash anchor)"
        family = "EtherRAT"
        confidence = "high"
        reference = "CTI-2026-0614-ETHERHIDING-KIT"
        hash = "bbc4150defcc2048213317ed7c9ff91c0b08f7507bec1faa1a2e8a309997121b"
    condition:
        hash.sha256(0, filesize) == "bbc4150defcc2048213317ed7c9ff91c0b08f7507bec1faa1a2e8a309997121b"
}

rule etherrat_node_resolver_heuristic
{
    meta:
        description = "Heuristic: Node.js stage resolving C2 via Ethereum RPC (EtherHiding)"
        family = "EtherRAT"
        confidence = "moderate"
        reference = "CTI-2026-0614-ETHERHIDING-KIT"
        note = "Behavioral hunt rule. Validate before action."
    strings:
        $rpc1 = "eth-mainnet.public.blastapi.io" ascii wide nocase
        $rpc2 = "eth.drpc.org" ascii wide nocase
        $rpc3 = "eth.merkle.io" ascii wide nocase
        $rpc4 = "ethereum-rpc.publicnode.com" ascii wide nocase
        $rpc5 = "gateway.tenderly.co" ascii wide nocase
        $rpc6 = "rpc.mevblocker.io" ascii wide nocase
        $rpc7 = "rpc.flashbots.net" ascii wide nocase
        $eth1 = "eth_call" ascii wide nocase
        $eth2 = "0x7d434425" ascii wide nocase          /* getString(address) */
        $eth3 = "0x3ca6280dac32fee85e9d3d81188d59eed7e4966e5b3df13a910924cf6ade2d47" ascii wide nocase
    condition:
        (3 of ($rpc*)) and (1 of ($eth*))
}

rule etherrat_kit_resolver_contract_bytecode
{
    meta:
        description = "On-chain resolver kit contract bytecode (EtherHiding setter/getter)"
        family = "EtherRAT"
        confidence = "high"
        reference = "CTI-2026-0614-ETHERHIDING-KIT"
        note = "Matches the deployed resolver runtime bytecode family. Use for on-chain bytecode triage."
    strings:
        $setter = "7fcaf666" ascii nocase                /* setString(string) selector */
        $getter = "7d434425" ascii nocase                /* getString(address) selector */
        $topic  = "3ca6280dac32fee85e9d3d81188d59eed7e4966e5b3df13a910924cf6ade2d47" ascii nocase
    condition:
        all of them
}
