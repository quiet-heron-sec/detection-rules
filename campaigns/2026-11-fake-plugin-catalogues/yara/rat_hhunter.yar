rule MAL_RAT_HHunter_Nov26 {
    meta:
        id = "4Zvv826r1nO22YwXuDUvew"
        fingerprint = "8c9832fa3d40b84ffbde2181cbf5da869c8f26ddf9484983df9a8871889e32ff"
        version = "1.0"
        score = 85
        minimum_yara = "4.2"
        date = "2026-11-08"
        modified = "2026-11-08"
        status = "TESTING"
        sharing = "TLP:CLEAR"
        source = "QUIET-HERON-SEC"
        author = "quiet-heron-sec"
        description = "Detects the remote access implant with the internal name hhunter, seen in the wild in October 2026"
        category = "MALWARE"
        malware = "HHUNTER"
        malware_type = "RAT"
        mitre_att = "T1021.005"
        reference = "https://bazaar.abuse.ch/sample/5410f0b624c2e396134e96545fea2ced1421b29e7af6a3023790335c0979d772/"
        hash = "5410f0b624c2e396134e96545fea2ced1421b29e7af6a3023790335c0979d772"
        yarahub_reference_md5 = "e806b75e180c4803b29747e60d1a538f"
        yarahub_reference_link = "https://github.com/quiet-heron-sec/detection-rules/blob/main/campaigns/2026-11-fake-plugin-catalogues/yara/rat_hhunter.yar"
        yarahub_uuid = "3ee5165c-ad3c-4d7d-9818-7c7844e96b55"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
        $s1 = "hhunter::vnc" ascii
        $s2 = "VNC-SPAWN" ascii
        $s3 = "ANC-V20" ascii
        $s4 = "__APPB_B64__" ascii
        $s5 = "UploadChunk" ascii
        $s6 = "ClipboardPush" ascii
        $s7 = "Hilmere" ascii

    condition:
        uint16(0) == 0x5A4D
        and filesize < 100MB
        and 4 of them
}

rule MAL_RAT_HHunter_Memory_Nov26 {
    meta:
        id = "4Hs3qMVzpxZE5lcFzoquu2"
        fingerprint = "117a1a6010789e89dccfec48a4366e9d676ecf9ef1b293c875c0be0a109997d4"
        version = "1.0"
        score = 80
        minimum_yara = "4.2"
        date = "2026-11-08"
        modified = "2026-11-08"
        status = "TESTING"
        sharing = "TLP:CLEAR"
        source = "QUIET-HERON-SEC"
        author = "quiet-heron-sec"
        description = "Detects the remote access implant with the internal name hhunter in process memory or memory dumps, where the injected image may have no MZ header"
        category = "MALWARE"
        malware = "HHUNTER"
        malware_type = "RAT"
        mitre_att = "T1021.005"
        reference = "https://bazaar.abuse.ch/sample/5410f0b624c2e396134e96545fea2ced1421b29e7af6a3023790335c0979d772/"
        hash = "5410f0b624c2e396134e96545fea2ced1421b29e7af6a3023790335c0979d772"
        yarahub_reference_md5 = "e806b75e180c4803b29747e60d1a538f"
        yarahub_reference_link = "https://github.com/quiet-heron-sec/detection-rules/blob/main/campaigns/2026-11-fake-plugin-catalogues/yara/rat_hhunter.yar"
        yarahub_uuid = "73af311b-69c0-4bcc-8ad1-085d054f943c"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
        $s1 = "hhunter::vnc" ascii
        $s2 = "VNC-SPAWN" ascii
        $s3 = "ANC-V20" ascii
        $s4 = "__APPB_B64__" ascii
        $s5 = "UploadChunk" ascii
        $s6 = "ClipboardPush" ascii
        $s7 = "Hilmere" ascii

    condition:
        5 of them
}
