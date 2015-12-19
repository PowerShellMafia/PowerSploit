@{

# Script module or binary module file associated with this manifest.
ModuleToProcess = 'CodeExecution.psm1'

# Version number of this module.
ModuleVersion = '3.0.0.0'

# ID used to uniquely identify this module
GUID = 'a8a6780b-e694-4aa4-b28d-646afa66733c'

# Author of this module
Author = 'Matthew Graeber'

# Company or vendor of this module
CompanyName = ''

# Copyright statement for this module
Copyright = 'BSD 3-Clause'

# Description of the functionality provided by this module
Description = 'PowerSploit Code Execution Module'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '2.0'

# Functions to export from this module
FunctionsToExport = '*'

# List of all files packaged with this module
FileList = 'CodeExecution.psm1', 'CodeExecution.psd1', 'Invoke-Shellcode.ps1', 'Invoke-DllInjection.ps1', 
               'Invoke-ReflectivePEInjection.ps1', 'Invoke-WmiCommand.ps1', 'Usage.md'
}
