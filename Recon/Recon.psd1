@{

# Script module or binary module file associated with this manifest.
ModuleToProcess = 'Recon.psm1'

# Version number of this module.
ModuleVersion = '3.0.0.0'

# ID used to uniquely identify this module
GUID = '7e775ad6-cd3d-4a93-b788-da067274c877'

# Author of this module
Author = 'Matthew Graeber', 'Will Schroeder'

# Copyright statement for this module
Copyright = 'BSD 3-Clause'

# Description of the functionality provided by this module
Description = 'PowerSploit Reconnaissance Module'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '2.0'

# Functions to export from this module
FunctionsToExport = @(
    'Get-ComputerDetails',
    'Get-HttpStatus',
    'Invoke-Portscan',
    'Invoke-ReverseDnsLookup',
    'Set-MacAttribute',
    'Copy-ClonedFile',
    'Convert-NameToSid',
    'Convert-SidToName',
    'Convert-NT4toCanonical',
    'Get-Proxy',
    'Get-PathAcl',
    'Get-NetDomain',
    'Get-NetForest',
    'Get-NetForestDomain',
    'Get-NetForestCatalog',
    'Get-NetDomainController',
    'Get-NetUser',
    'Add-NetUser',
    'Get-UserProperty',
    'Find-UserField',
    'Get-UserEvent',
    'Get-ObjectAcl',
    'Add-ObjectAcl',
    'Invoke-ACLScanner',
    'Get-NetComputer',
    'Get-ADObject',
    'Set-ADObject',
    'Get-ComputerProperty',
    'Find-ComputerField',
    'Get-NetOU',
    'Get-NetSite',
    'Get-NetSubnet',
    'Get-NetGroup',
    'Get-NetGroupMember',
    'Get-NetFileServer',
    'Get-DFSshare',
    'Get-NetGPO',
    'Get-NetGPOGroup',
    'Find-GPOLocation',
    'Find-GPOComputerAdmin',
    'Get-DomainPolicy',
    'Get-NetLocalGroup',
    'Get-NetShare',
    'Get-NetLoggedon',
    'Get-NetSession',
    'Get-NetRDPSession',
    'Invoke-CheckLocalAdminAccess',
    'Get-LastLoggedOn',
    'Get-CachedRDPConnection',
    'Get-NetProcess',
    'Find-InterestingFile',
    'Invoke-UserHunter',
    'Invoke-ProcessHunter',
    'Invoke-EventHunter',
    'Invoke-ShareFinder',
    'Invoke-FileFinder',
    'Find-LocalAdminAccess',
    'Get-ExploitableSystem',
    'Invoke-EnumerateLocalAdmin',
    'Get-NetDomainTrust',
    'Get-NetForestTrust',
    'Find-ForeignUser',
    'Find-ForeignGroup',
    'Invoke-MapDomainTrust'
)

# List of all files packaged with this module
FileList = 'Recon.psm1', 'Recon.psd1', 'PowerView.ps1', 'Get-HttpStatus.ps1', 'Invoke-ReverseDnsLookup.ps1',
               'Invoke-Portscan.ps1', 'Get-ComputerDetails.ps1', 'README.md'

}
