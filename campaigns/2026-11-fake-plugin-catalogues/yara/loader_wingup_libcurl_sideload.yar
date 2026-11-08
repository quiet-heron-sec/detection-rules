import "pe"

rule MAL_Loader_Fake_Libcurl_WinGup_Nov26 {
    meta:
        id = "3EZwlgB1Dcyonzmy37O98r"
        fingerprint = "1b653f20de3a666423188d979fe7d4c4e5b1226871b8500d82b713bca6015398"
        version = "1.0"
        score = 80
        minimum_yara = "4.2"
        date = "2026-11-08"
        modified = "2026-11-08"
        status = "TESTING"
        sharing = "TLP:CLEAR"
        source = "QUIET-HERON-SEC"
        author = "quiet-heron-sec"
        description = "Detects a fake libcurl.dll side-loaded by WinGup that exports the curl API without any socket import"
        category = "MALWARE"
        malware = "WINGUP LIBCURL LOADER"
        malware_type = "LOADER"
        mitre_att = "T1574.001"
        reference = "https://www.virustotal.com/gui/file/22dadd303759f12dc11a17b7612178dd5a8615cbf365a3a617faa181438c8273"
        hash = "22dadd303759f12dc11a17b7612178dd5a8615cbf365a3a617faa181438c8273"
        yarahub_reference_md5 = "c82d0d6f46d3ce0b587b4d93afab1919"
        yarahub_reference_link = "https://github.com/quiet-heron-sec/detection-rules/blob/main/campaigns/2026-11-fake-plugin-catalogues/yara/loader_wingup_libcurl_sideload.yar"
        yarahub_uuid = "ff310324-874f-49ea-b0f9-624491237a2d"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    condition:
        uint16(0) == 0x5A4D
        and filesize < 40MB
        and pe.is_dll()
        and pe.exports("curl_easy_init")
        and pe.exports("curl_easy_perform")
        and pe.exports("curl_easy_setopt")
        and pe.imports(/ws2_32\.dll/i, /.*/) == 0
        and pe.imports("KERNEL32.dll", "CreateProcessA")
        and pe.imports("KERNEL32.dll", "VirtualProtect")
}

rule MAL_Loader_Fake_Libcurl_22dadd30_Build_Nov26 {
    meta:
        id = "11mSCOQAfChtVWqiRfk7Gq"
        fingerprint = "b84e29c14357902067edd1efb450ead33fee50cd3c87359f1949df3d7bc9435c"
        version = "1.0"
        score = 90
        minimum_yara = "4.2"
        date = "2026-11-08"
        modified = "2026-11-08"
        status = "TESTING"
        sharing = "TLP:CLEAR"
        source = "QUIET-HERON-SEC"
        author = "quiet-heron-sec"
        description = "Detects a November 2026 build of a fake libcurl.dll loader side-loaded by WinGup"
        category = "MALWARE"
        malware = "WINGUP LIBCURL LOADER"
        malware_type = "LOADER"
        reference = "https://www.virustotal.com/gui/file/22dadd303759f12dc11a17b7612178dd5a8615cbf365a3a617faa181438c8273"
        hash = "22dadd303759f12dc11a17b7612178dd5a8615cbf365a3a617faa181438c8273"
        yarahub_reference_md5 = "c82d0d6f46d3ce0b587b4d93afab1919"
        yarahub_reference_link = "https://github.com/quiet-heron-sec/detection-rules/blob/main/campaigns/2026-11-fake-plugin-catalogues/yara/loader_wingup_libcurl_sideload.yar"
        yarahub_uuid = "de39dbaa-3cc3-4ee5-bfa5-cb1818fcd684"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
        $words1 = "et module schema frame result region target footer socket method string object plugin anchor border" ascii
        $words2 = "e sensor border index footer engine source string plugin signal sample socket" ascii

    condition:
        uint16(0) == 0x5A4D
        and filesize < 40MB
        and pe.is_dll()
        and pe.exports("curl_easy_init")
        and for any s in pe.sections : ( s.name == "aqgjcapy" )
        and 1 of ($words*)
}
