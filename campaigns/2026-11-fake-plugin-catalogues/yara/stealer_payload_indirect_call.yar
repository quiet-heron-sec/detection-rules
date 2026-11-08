import "pe"

rule MAL_Stealer_Payload_IndirectCall_Nov26 {
    meta:
        id = "7UUYEXY958tyIo4Guh0x9v"
        fingerprint = "6ef2cb80b4097a7c1f3d66238d10f4e39bc14e27b9abcce64792a2f4fe56210f"
        version = "1.0"
        score = 75
        minimum_yara = "4.2"
        date = "2026-11-08"
        modified = "2026-11-08"
        status = "TESTING"
        sharing = "TLP:CLEAR"
        source = "QUIET-HERON-SEC"
        author = "quiet-heron-sec"
        description = "Detects a stealer payload of an AutoIt loader by its obfuscated indirect-call stub"
        category = "MALWARE"
        malware = "UNATTRIBUTED STEALER"
        malware_type = "INFOSTEALER"
        mitre_att = "T1027"
        reference = "https://bazaar.abuse.ch/sample/27eab923aeb79a3054f4677539d9c652c3211e44f251d76347c5ebdfe0333c9f/"
        hash = "27eab923aeb79a3054f4677539d9c652c3211e44f251d76347c5ebdfe0333c9f"
        yarahub_reference_md5 = "9c9ab0455b67193fefbb429ffb770e04"
        yarahub_reference_link = "https://github.com/quiet-heron-sec/detection-rules/blob/main/campaigns/2026-11-fake-plugin-catalogues/yara/stealer_payload_indirect_call.yar"
        yarahub_uuid = "98f7b412-215d-4c06-a6ef-2fdd4934112f"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
        // imul eax, ebp, imm32 ; mov rdx, rbx ; mov ecx, ebp ; add edi, eax ; call
        $stub = { 69 C5 ?? ?? ?? ?? 48 89 DA 8B CD 01 C7 E8 }
        // mov ecx, imm32 ; mov r8d, imm32 ; mov r9, <r64> ; call  (38 sites, five source registers)
        $site = { B9 ?? ?? ?? ?? 41 B8 ?? ?? ?? ?? 4? 89 ?? E8 }

    condition:
        uint16(0) == 0x5A4D
        and filesize < 5MB
        and pe.is_64bit()
        and pe.number_of_imports < 6
        and $stub
        and #site > 20
}

rule MAL_Stealer_Payload_27eab923_Build_Nov26 {
    meta:
        id = "5rzdJbW6MT5zkdKtfhrd7T"
        fingerprint = "15ddeb9a22c90292715f2814b64df82653c38fa8040e4a316ac6a3757ecd73f5"
        version = "1.0"
        score = 90
        minimum_yara = "4.2"
        date = "2026-11-08"
        modified = "2026-11-08"
        status = "TESTING"
        sharing = "TLP:CLEAR"
        source = "QUIET-HERON-SEC"
        author = "quiet-heron-sec"
        description = "Detects a November 2026 build of a stealer payload injected by an AutoIt loader"
        category = "MALWARE"
        malware = "UNATTRIBUTED STEALER"
        malware_type = "INFOSTEALER"
        reference = "https://bazaar.abuse.ch/sample/27eab923aeb79a3054f4677539d9c652c3211e44f251d76347c5ebdfe0333c9f/"
        hash = "27eab923aeb79a3054f4677539d9c652c3211e44f251d76347c5ebdfe0333c9f"
        yarahub_reference_md5 = "9c9ab0455b67193fefbb429ffb770e04"
        yarahub_reference_link = "https://github.com/quiet-heron-sec/detection-rules/blob/main/campaigns/2026-11-fake-plugin-catalogues/yara/stealer_payload_indirect_call.yar"
        yarahub_uuid = "a45f574f-770b-4053-abda-f9049cbbe196"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
        $pdb = "raspogvoavorn.pdb" ascii
        $pool1 = "3nsh568acof23z66fikq42e3ak5rme0392" ascii
        $pool2 = "uq4r9ibju9co7r26fqzhck904brk2gpxeo" ascii
        $stub = { 69 C5 FD 70 A7 08 48 89 DA 8B CD 01 C7 E8 }

    condition:
        uint16(0) == 0x5A4D
        and filesize < 5MB
        and 2 of them
}
