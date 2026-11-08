rule SUSP_AutoIt_A3X_Padded_Nov26 {
    meta:
        id = "5b6dENa2lByzZOyaOEFhHt"
        fingerprint = "786be87d4c64ee936811c5a0084ec456f253c15547e372f47d62f6ea8eb9083b"
        version = "1.0"
        score = 65
        minimum_yara = "4.2"
        date = "2026-11-08"
        modified = "2026-11-08"
        status = "TESTING"
        sharing = "TLP:CLEAR"
        source = "QUIET-HERON-SEC"
        author = "quiet-heron-sec"
        description = "Detects a compiled AutoIt script (a3x) whose header follows a block of padding, as dropped by SFX loaders"
        category = "TECHNIQUE"
        technique = "OBFUSCATION"
        mitre_att = "T1027"
        reference = "https://bazaar.abuse.ch/sample/3592f41d2ed3d321e9f1a77c6a2d39d390264ee477b04eb3f65dfddb8af7acb4/"
        hash = "3592f41d2ed3d321e9f1a77c6a2d39d390264ee477b04eb3f65dfddb8af7acb4"
        yarahub_reference_md5 = "6d3b6fe05798c8c4e8f3e2004d5e5f14"
        yarahub_uuid = "ea81b98c-766d-4a48-90b7-0ed7f4ccc6db"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
        // a3x identifier followed by AU3!EA06
        $a3x = { A3 48 4B BE 98 6C 4A A9 99 4C 53 0A 86 D6 48 7D 41 55 33 21 45 41 30 36 }

    condition:
        uint16(0) != 0x5A4D
        and filesize > 64KB and filesize < 50MB
        and $a3x
        and @a3x[1] > 1024
        and not $a3x at 0
}

rule MAL_AutoIt_A3X_Drove_Build_Nov26 {
    meta:
        id = "75QazC87ivjL6glNBPN1oj"
        fingerprint = "d55aab0d0b37dde8ae559adb36db9f0768cbc11fa9585b16680ec408ddef4237"
        version = "1.0"
        score = 90
        minimum_yara = "4.2"
        date = "2026-11-08"
        modified = "2026-11-08"
        status = "TESTING"
        sharing = "TLP:CLEAR"
        source = "QUIET-HERON-SEC"
        author = "quiet-heron-sec"
        description = "Detects the Drove.au3 AutoIt loader script seen in the wild in November 2026"
        category = "MALWARE"
        malware = "AUTOIT SFX LOADER"
        malware_type = "LOADER"
        mitre_att = "T1055.012"
        reference = "https://bazaar.abuse.ch/sample/3592f41d2ed3d321e9f1a77c6a2d39d390264ee477b04eb3f65dfddb8af7acb4/"
        hash = "3592f41d2ed3d321e9f1a77c6a2d39d390264ee477b04eb3f65dfddb8af7acb4"
        yarahub_reference_md5 = "6d3b6fe05798c8c4e8f3e2004d5e5f14"
        yarahub_uuid = "c3b58498-64ab-4ec1-b797-3b8a9c7f1ebc"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
        $head = { 42 1C 7D 92 E5 66 D5 31 EF 7C F5 55 AD FF A3 C7 }
        $a3x = { A3 48 4B BE 98 6C 4A A9 99 4C 53 0A 86 D6 48 7D 41 55 33 21 45 41 30 36 }

    condition:
        $head at 0
        and $a3x at 8157
}
