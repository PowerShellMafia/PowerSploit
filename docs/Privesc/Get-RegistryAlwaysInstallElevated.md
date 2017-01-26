# Get-RegistryAlwaysInstallElevated

## SYNOPSIS
Checks if any of the AlwaysInstallElevated registry keys are set.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None

## SYNTAX

```
Get-RegistryAlwaysInstallElevated
```

## DESCRIPTION
Returns $True if the HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
or the HKCU:SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated keys
are set, $False otherwise.
If one of these keys are set, then all .MSI files run with
elevated permissions, regardless of current user permissions.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-RegistryAlwaysInstallElevated
```

Returns $True if any of the AlwaysInstallElevated registry keys are set.

## PARAMETERS

## INPUTS

## OUTPUTS

### System.Boolean

$True if RegistryAlwaysInstallElevated is set, $False otherwise.

## NOTES

## RELATED LINKS

