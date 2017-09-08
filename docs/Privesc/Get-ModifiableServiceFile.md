# Get-ModifiableServiceFile

## SYNOPSIS
Enumerates all services and returns vulnerable service files.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Test-ServiceDaclPermission, Get-ModifiablePath

## SYNTAX

```
Get-ModifiableServiceFile
```

## DESCRIPTION
Enumerates all services by querying the WMI win32_service class.
For each service,
it takes the pathname (aka binPath) and passes it to Get-ModifiablePath to determine
if the current user has rights to modify the service binary itself or any associated
arguments.
If the associated binary (or any configuration files) can be overwritten,
privileges may be able to be escalated.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-ModifiableServiceFile
```

Get a set of potentially exploitable service binares/config files.

## PARAMETERS

## INPUTS

## OUTPUTS

### PowerUp.ModifiablePath

## NOTES

## RELATED LINKS

