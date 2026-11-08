rule MAL_Stealer_Mops_V3_Nov26 {
    meta:
        id = "2U1mAaTits9tiCaxEjXmbI"
        fingerprint = "593139bdceed4f020c98ec516834c6b8b1638f10156ab2dde07e017ea2e8e246"
        version = "1.0"
        score = 80
        minimum_yara = "4.2"
        date = "2026-11-08"
        modified = "2026-11-08"
        status = "TESTING"
        sharing = "TLP:CLEAR"
        source = "QUIET-HERON-SEC"
        author = "quiet-heron-sec"
        description = "Detects Mops Stealer V3 DLLs by their mutex names, log header fields and output file paths"
        category = "MALWARE"
        malware = "MOPS STEALER"
        malware_type = "INFOSTEALER"
        mitre_att = "T1555.003"
        reference = "https://bazaar.abuse.ch/sample/1c850a5b877770dd831c68e2b6c9681419e63533c2f04cf9bdfa8f7fa6756585/"
        hash = "1c850a5b877770dd831c68e2b6c9681419e63533c2f04cf9bdfa8f7fa6756585"
        hash = "3c110de70db7225573f6bd937a7704423bce6c03fad5fac3ea3fb5bacf130d50"
        yarahub_reference_md5 = "2993c58af93e862b90f5fccdaf740231"
        yarahub_reference_link = "https://github.com/quiet-heron-sec/detection-rules/blob/main/campaigns/2026-11-fake-plugin-catalogues/yara/stealer_mops_v3.yar"
        yarahub_uuid = "894738a7-05fe-43fe-a2ce-d93ea1562ae5"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
        $mutex1 = "Global\\RuntimeBrokerAds" ascii
        $mutex2 = "Global\\StealerLib" ascii
        $log1 = "- Mops Stealer V3: " ascii
        $log2 = "- Lid: %worker%" ascii
        $log3 = "- Time Save Log: %timesave%" ascii
        $path1 = "Applications/Exbo/MemoryStrings.txt" ascii
        $path2 = "Applications/Obs/OBS_ServiceKeys.txt" ascii
        $path3 = "Applications/Debug/TimesExecutions.txt" ascii

    condition:
        uint16(0) == 0x5A4D
        and filesize < 5MB
        and 5 of them
}
