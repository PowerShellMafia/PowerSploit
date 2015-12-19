@{
# Script module or binary module file associated with this manifest.
ModuleToProcess = 'PowerSploit.psm1'

# Version number of this module.
ModuleVersion = '3.0.0.0'

# ID used to uniquely identify this module
GUID = '6753b496-d842-40a3-924a-0f09e248640c'

# Author of this module
Author = 'Matthew Graeber'

# Copyright statement for this module
Copyright = 'BSD 3-Clause'

# Description of the functionality provided by this module
Description = 'PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers and red team operator during all phases of an engagement.'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '2.0'

# Functions to export from this module
FunctionsToExport = @(
    'Add-NetUser',
    'Add-ObjectAcl',
    'Add-Persistence',
    'Convert-NameToSid',
    'Convert-NT4toCanonical',
    'Convert-SidToName',
    'Copy-ClonedFile',
    'Find-AVSignature',
    'Find-ComputerField',
    'Find-DLLHijack',
    'Find-ForeignGroup',
    'Find-ForeignUser',
    'Find-GPOComputerAdmin',
    'Find-GPOLocation',
    'Find-InterestingFile',
    'Find-LocalAdminAccess',
    'Find-PathHijack',
    'Find-UserField',
    'Get-ADObject',
    'Get-ApplicationHost',
    'Get-CachedRDPConnection',
    'Get-ComputerDetails',
    'Get-ComputerProperty',
    'Get-DFSshare',
    'Get-DomainPolicy',
    'Get-ExploitableSystem',
    'Get-GPPPassword',
    'Get-HttpStatus',
    'Get-Keystrokes',
    'Get-LastLoggedOn',
    'Get-NetComputer',
    'Get-NetDomain',
    'Get-NetDomainController',
    'Get-NetDomainTrust',
    'Get-NetFileServer',
    'Get-NetForest',
    'Get-NetForestCatalog',
    'Get-NetForestDomain',
    'Get-NetForestTrust',
    'Get-NetGPO',
    'Get-NetGPOGroup',
    'Get-NetGroup',
    'Get-NetGroupMember',
    'Get-NetLocalGroup',
    'Get-NetLoggedon',
    'Get-NetOU',
    'Get-NetProcess',
    'Get-NetRDPSession',
    'Get-NetSession',
    'Get-NetShare',
    'Get-NetSite',
    'Get-NetSubnet',
    'Get-NetUser',
    'Get-ObjectAcl',
    'Get-PathAcl',
    'Get-Proxy',
    'Get-RegAlwaysInstallElevated',
    'Get-RegAutoLogon',
    'Get-SecurityPackages',
    'Get-ServiceDetail',
    'Get-ServiceFilePermission',
    'Get-ServicePermission',
    'Get-ServiceUnquoted',
    'Get-TimedScreenshot',
    'Get-UnattendedInstallFile',
    'Get-UserEvent',
    'Get-UserProperty',
    'Get-VaultCredential',
    'Get-VolumeShadowCopy',
    'Get-VulnAutoRun',
    'Get-VulnSchTask',
    'Get-Webconfig',
    'Install-ServiceBinary',
    'Install-SSP',
    'Invoke-ACLScanner',
    'Invoke-AllChecks',
    'Invoke-CheckLocalAdminAccess',
    'Invoke-CredentialInjection',
    'Invoke-DllInjection',
    'Invoke-EnumerateLocalAdmin',
    'Invoke-EventHunter',
    'Invoke-FileFinder',
    'Invoke-MapDomainTrust',
    'Invoke-Mimikatz',
    'Invoke-NinjaCopy',
    'Invoke-Portscan',
    'Invoke-ProcessHunter',
    'Invoke-ReflectivePEInjection',
    'Invoke-ReverseDnsLookup',
    'Invoke-ServiceAbuse',
    'Invoke-ShareFinder',
    'Invoke-Shellcode',
    'Invoke-TokenManipulation',
    'Invoke-UserHunter',
    'Invoke-WmiCommand',
    'Mount-VolumeShadowCopy',
    'New-ElevatedPersistenceOption',
    'New-UserPersistenceOption',
    'New-VolumeShadowCopy',
    'Out-CompressedDll',
    'Out-EncodedCommand',
    'Out-EncryptedScript',
    'Out-Minidump',
    'Remove-Comments',
    'Remove-VolumeShadowCopy',
    'Restore-ServiceBinary',
    'Set-ADObject',
    'Set-CriticalProcess',
    'Set-MacAttribute',
    'Set-MasterBootRecord',
    'Write-HijackDll',
    'Write-ServiceBinary',
    'Write-UserAddMSI'
)

# List of all modules packaged with this module.
ModuleList = @( @{ModuleName = 'AntivirusBypass'; ModuleVersion = '3.0.0.0'; GUID = '7cf9de61-2bfc-41b4-a397-9d7cf3a8e66b'},
                @{ModuleName = 'CodeExecution'; ModuleVersion = '3.0.0.0'; GUID = 'a8a6780b-e694-4aa4-b28d-646afa66733c'},
                @{ModuleName = 'Exfiltration'; ModuleVersion = '3.0.0.0'; GUID = '75dafa99-1402-4e29-b5d4-6c87da2b323a'},
                @{ModuleName = 'Recon'; ModuleVersion = '3.0.0.0'; GUID = '7e775ad6-cd3d-4a93-b788-da067274c877'},
                @{ModuleName = 'ScriptModification'; ModuleVersion = '3.0.0.0'; GUID = 'a4d86266-b39b-437a-b5bb-d6f99aa6e610'},
                @{ModuleName = 'Persistence'; ModuleVersion = '3.0.0.0'; GUID = '633d0f10-a056-41da-869d-6d2f75430195'},
                @{ModuleName = 'PrivEsc'; ModuleVersion = '3.0.0.0'; GUID = 'efb2a78f-a069-4bfd-91c2-7c7c0c225f56'} )

PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        Tags = @('security','pentesting','red team','offense')

        # A URL to the license for this module.
        LicenseUri = 'http://www.apache.org/licenses/LICENSE-2.0.html'

        # A URL to the main website for this project.
        ProjectUri = 'https://github.com/PowerShellMafia/PowerSploit'

    }

}

}
