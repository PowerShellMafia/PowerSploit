@{

# Script module or binary module file associated with this manifest.
ModuleToProcess = 'ReverseEngineering.psm1'

# Version number of this module.
ModuleVersion = '1.0.0.0'

# ID used to uniquely identify this module
GUID = 'cbffaf47-c55a-4901-92e7-8d794fbe1fff'

# Author of this module
Author = 'Matthew Graeber'

# Company or vendor of this module
CompanyName = ''

# Copyright statement for this module
Copyright = 'BSD 3-Clause'

# Description of the functionality provided by this module
Description = 'PowerSploit Reverse Engineering Module'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '2.0'

# Name of the Windows PowerShell host required by this module
# PowerShellHostName = ''

# Minimum version of the Windows PowerShell host required by this module
# PowerShellHostVersion = ''

# Minimum version of the .NET Framework required by this module
# DotNetFrameworkVersion = ''

# Minimum version of the common language runtime (CLR) required by this module
# CLRVersion = ''

# Processor architecture (None, X86, Amd64) required by this module
# ProcessorArchitecture = ''

# Modules that must be imported into the global environment prior to importing this module
# RequiredModules = @()

# Assemblies that must be loaded prior to importing this module
# RequiredAssemblies = @()

# Script files (.ps1) that are run in the caller's environment prior to importing this module.
# ScriptsToProcess = ''

# Type files (.ps1xml) to be loaded when importing this module
# TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
FormatsToProcess = 'Get-PEB.format.ps1xml', 'Get-NtSystemInformation.format.ps1xml'

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
# NestedModules = @()

# Functions to export from this module
FunctionsToExport = '*'

# Cmdlets to export from this module
CmdletsToExport = '*'

# Variables to export from this module
VariablesToExport = ''

# Aliases to export from this module
AliasesToExport = ''

# List of all modules packaged with this module.
ModuleList = @(@{ModuleName = 'ReverseEngineering'; ModuleVersion = '1.0.0.0'; GUID = 'cbffaf47-c55a-4901-92e7-8d794fbe1fff'})

# List of all files packaged with this module
FileList = 'ReverseEngineering.psm1', 'ReverseEngineering.psd1', 'Get-ILDisassembly.ps1', 'Get-NtSystemInformation.format.ps1xml',
               'Get-NtSystemInformation.ps1', 'Get-Member.ps1', 'Get-MethodAddress.ps1', 'Get-PEB.format.ps1xml',
               'Get-PEB.ps1', 'Get-Strings.ps1', 'Get-StructFromMemory.ps1', 'ConvertTo-String.ps1',
               'New-Object.ps1', 'Usage.md'

# Private data to pass to the module specified in RootModule/ModuleToProcess
# PrivateData = ''

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}

