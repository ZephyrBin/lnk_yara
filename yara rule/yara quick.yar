rule QuickDetectionPowershell
{
	strings:
		$a1 = "powershell" nocase
		$a2 = "powershell" ascii wide nocase
		$a3 = {70 00 6F 00 77 00 65 00 72 00 73 00 68 00 65 00 6C 00 6C 00}
		$a4 = {70 6F 77 65 72 73 68 65 6C 6C}
	condition:
		any of ($a*)
}