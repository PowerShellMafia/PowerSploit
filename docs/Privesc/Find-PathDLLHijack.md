# Find-PathDLLHijack

## SYNOPSIS
Finds all directories in the system %PATH% that are modifiable by the current user.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-ModifiablePath

## SYNTAX

```
Find-PathDLLHijack
```

## DESCRIPTION
Enumerates the paths stored in Env:Path (%PATH) and filters each through Get-ModifiablePath
to return the folder paths the current user can write to.
On Windows 7, if wlbsctrl.dll is
written to one of these paths, execution for the IKEEXT can be hijacked due to DLL search
order loading.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Find-PathDLLHijack
```

Finds all %PATH% .DLL hijacking opportunities.

## PARAMETERS

## INPUTS

## OUTPUTS

### PowerUp.HijackableDLL.Path

## NOTES

## RELATED LINKS

[http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)

