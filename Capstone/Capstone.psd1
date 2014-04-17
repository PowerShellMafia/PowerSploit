@{

# Script module or binary module file associated with this manifest.
ModuleToProcess = 'Capstone.psm1'

# Version number of this module.
ModuleVersion = '2.0.0.0'

# ID used to uniquely identify this module
GUID = 'bc335667-02fd-46c4-a3d9-0a5113c9c03b'

# Author of this module
Author = 'Matthew Graeber'

# Copyright statement for this module
Copyright = 'see LICENSE.TXT'

# Description of the functionality provided by this module
Description = 'Capstone Disassembly Framework Binding Module'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '3.0'

# Minimum version of the common language runtime (CLR) required by this module
CLRVersion = '4.0'

# Assemblies that must be loaded prior to importing this module
RequiredAssemblies = 'lib/capstone.dll'

# Format files (.ps1xml) to be loaded when importing this module
FormatsToProcess = 'Get-CSDisassembly.format.ps1xml'

# Functions to export from this module
FunctionsToExport = '*'

# List of all modules packaged with this module.
ModuleList = @(@{ModuleName = 'Capstone'; ModuleVersion = '1.0.0.0'; GUID = 'bc335667-02fd-46c4-a3d9-0a5113c9c03b'})

# List of all files packaged with this module
FileList = 'Capstone.psm1',
           'Capstone.psd1',
           'Get-CSDisassembly.format.ps1xml',
           'LICENSE.TXT',
           'README', 
           'lib/capstone.dll',
           'lib/x86/libcapstone.dll',
           'lib/x64/libcapstone.dll'
}
