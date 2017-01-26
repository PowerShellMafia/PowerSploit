# Get-ModifiableRegistryAutoRun

## SYNOPSIS
Returns any elevated system autoruns in which the current user can
modify part of the path string.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-ModifiablePath

## SYNTAX

```
Get-ModifiableRegistryAutoRun
```

## DESCRIPTION
Enumerates a number of autorun specifications in HKLM and filters any
autoruns through Get-ModifiablePath, returning any file/config locations
in the found path strings that the current user can modify.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-ModifiableRegistryAutoRun
```

Return vulneable autorun binaries (or associated configs).

## PARAMETERS

## INPUTS

## OUTPUTS

### PowerUp.ModifiableRegistryAutoRun

Custom PSObject containing results.

## NOTES

## RELATED LINKS

