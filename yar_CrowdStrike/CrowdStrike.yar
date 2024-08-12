import "hash"

rule Detect_Crowdstrike_UpdateIsuue_Campaign_FileHashes 
{
    meta:
        description = "Detect files with specific MD5 hashes"
        author = "CRT"
        date = "2024-07-22"
        reference = "CYFIRMA Research"

    condition:
        hash.md5(0, filesize) == "1e84736efce206dc973acbc16540d3e5" or
        hash.md5(0, filesize) == "7daa2b7fe529b45101a399b5ebf0a416" or
        hash.md5(0, filesize) == "9d255e04106ba7dcbd0bcb549e9a5a4e" or
        hash.md5(0, filesize) == "11d67598baffee39cb3827251f2a255e" or
        hash.md5(0, filesize) == "371c165e3e3c1a000051b78d7b0e7e79" or
        hash.md5(0, filesize) == "21068dfd733435c866312d35b9432733" or
        hash.md5(0, filesize) == "28f0ccf746f952f94ff434ca989b7814" or
        hash.md5(0, filesize) == "451049d3ac526f1abdd704c3b1fed580" or
        hash.md5(0, filesize) == "630991830afe0b969bd0995e697ab16e" or
        hash.md5(0, filesize) == "849070ebd34cbaedc525599d6c3f8914" or
        hash.md5(0, filesize) == "8274785d42b79444767fb0261746fe91" or
        hash.md5(0, filesize) == "da03ebd2a8448f53d1bd9e16fc903168" or
}

rule Detect_Crowdstrike_Data_Wiper
{
    meta:
        description = "Fake CrowdStrike Patch Malware Data Wiper - Detection Rule"
        author = "CRT"
        date = "2024-07-22"
        reference = "CYFIRMA Research"
        version = "1.0"

    strings:
        $bytes_mz = {4D 5A 90 00}
        $bytes_dt = {DA E2 47 4F}
        $str1 = "CrowdStrike Updater.exe" ascii wide nocase
        $str2 = "NullsoftInst" ascii wide nocase
        $str3 = "VLC media player0" ascii wide nocase
        
    condition:
        filesize >= 5MB and
        $bytes_mz at 0 and
        $bytes_dt at 216 and
        all of them
}