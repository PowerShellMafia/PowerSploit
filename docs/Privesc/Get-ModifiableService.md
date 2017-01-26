# Get-ModifiableService

## SYNOPSIS
Enumerates all services and returns services for which the current user can modify the binPath.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Test-ServiceDaclPermission, Get-ServiceDetail

## SYNTAX

```
Get-ModifiableService
```

## DESCRIPTION
Enumerates all services using Get-Service and uses Test-ServiceDaclPermission to test if
the current user has rights to change the service configuration.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-ModifiableService
```

Get a set of potentially exploitable services.

## PARAMETERS

## INPUTS

## OUTPUTS

### PowerUp.ModifiablePath

## NOTES

## RELATED LINKS

