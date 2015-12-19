@{

# Script module or binary module file associated with this manifest.
ModuleToProcess = 'Privesc.psm1'

# Version number of this module.
ModuleVersion = '3.0.0.0'

# ID used to uniquely identify this module
GUID = 'efb2a78f-a069-4bfd-91c2-7c7c0c225f56'

# Author of this module
Author = 'Will Schroder'

# Copyright statement for this module
Copyright = 'BSD 3-Clause'

# Description of the functionality provided by this module
Description = 'PowerSploit Privesc Module'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '2.0'

# Functions to export from this module
FunctionsToExport = @(  
    'Get-ServiceUnquoted',
    'Get-ServiceFilePermission',
    'Get-ServicePermission',
    'Get-ServiceDetail',
    'Invoke-ServiceAbuse',
    'Write-ServiceBinary',
    'Install-ServiceBinary',
    'Restore-ServiceBinary',
    'Find-DLLHijack',
    'Find-PathHijack',
    'Write-HijackDll',
    'Get-RegAlwaysInstallElevated',
    'Get-RegAutoLogon',
    'Get-VulnAutoRun',
    'Get-VulnSchTask',
    'Get-UnattendedInstallFile',
    'Get-Webconfig',
    'Get-ApplicationHost',
    'Write-UserAddMSI',
    'Invoke-AllChecks'
)

# List of all files packaged with this module
FileList = 'Privesc.psm1', 'PowerUp.ps1', 'README.md'

}

