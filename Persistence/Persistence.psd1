@{

# Script module or binary module file associated with this manifest.
ModuleToProcess = 'Persistence.psm1'

# Version number of this module.
ModuleVersion = '1.0.0.0'

# ID used to uniquely identify this module
GUID = '633d0f10-a056-41da-869d-6d2f75430195'

# Author of this module
Author = 'Matthew Graeber'

# Copyright statement for this module
Copyright = 'BSD 3-Clause'

# Description of the functionality provided by this module
Description = 'PowerSploit Persistence Module'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '2.0'

# Functions to export from this module
FunctionsToExport = '*'

# Cmdlets to export from this module
CmdletsToExport = '*'

# List of all modules packaged with this module.
ModuleList = @(@{ModuleName = 'Persistence'; ModuleVersion = '1.0.0.0'; GUID = '633d0f10-a056-41da-869d-6d2f75430195'})

# List of all files packaged with this module
FileList = 'Persistence.psm1', 'Persistence.psd1', 'Usage.md'

}
