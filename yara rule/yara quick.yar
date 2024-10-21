rule QuickDetectionPowershell
{
	strings:
		$a = "powershell" nocase
	condition:
		$a
}