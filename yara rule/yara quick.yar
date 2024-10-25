rule SUSP_LNK_Flags
{
	meta:
		author = "JowonReady"
		date = "2024/10/24"
		threat_level = 1
	
	condition:
		uint32(0) == 0x4C and
		(uint32(0x14) & 0x20) == 0x20 and
		(uint32(0x3C) & 0x07) == 0x07
}