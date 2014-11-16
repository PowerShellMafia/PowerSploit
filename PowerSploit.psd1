@{
# Script module or binary module file associated with this manifest.
ModuleToProcess = 'PowerSploit.psm1'

# Version number of this module.
ModuleVersion = '1.0.0.0'

# ID used to uniquely identify this module
GUID = '6753b496-d842-40a3-924a-0f09e248640c'

# Author of this module
Author = 'Matthew Graeber'

# Company or vendor of this module
CompanyName = ''

# Copyright statement for this module
Copyright = 'BSD 3-Clause'

# Description of the functionality provided by this module
Description = 'PowerSploit Root Module'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '2.0'

# Functions to export from this module
FunctionsToExport = '*'

# Cmdlets to export from this module
CmdletsToExport = '*'

# Variables to export from this module
VariablesToExport = ''

# Aliases to export from this module
AliasesToExport = ''

# List of all modules packaged with this module.
ModuleList = @( @{ModuleName = 'AntivirusBypass'; ModuleVersion = '1.0.0.0'; GUID = '7cf9de61-2bfc-41b4-a397-9d7cf3a8e66b'},
                @{ModuleName = 'CodeExecution'; ModuleVersion = '1.0.0.0'; GUID = 'a8a6780b-e694-4aa4-b28d-646afa66733c'},
                @{ModuleName = 'Exfiltration'; ModuleVersion = '1.0.0.0'; GUID = '75dafa99-1402-4e29-b5d4-6c87da2b323a'},
                @{ModuleName = 'Recon'; ModuleVersion = '1.0.0.0'; GUID = '7e775ad6-cd3d-4a93-b788-da067274c877'},
                @{ModuleName = 'ScriptModification'; ModuleVersion = '1.0.0.0'; GUID = 'a4d86266-b39b-437a-b5bb-d6f99aa6e610'},
                @{ModuleName = 'Persistence'; ModuleVersion = '1.0.0.0'; GUID = '633d0f10-a056-41da-869d-6d2f75430195'} )
}
