# Get-UnquotedService

## SYNOPSIS
Get-UnquotedService Returns the name and binary path for services with unquoted paths
that also have a space in the name.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-ModifiablePath, Test-ServiceDaclPermission

## SYNTAX

```
Get-UnquotedService
```

## DESCRIPTION
Uses Get-WmiObject to query all win32_service objects and extract out
the binary pathname for each.
Then checks if any binary paths have a space
and aren't quoted.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-UnquotedService
```

Get a set of potentially exploitable services.

## PARAMETERS

## INPUTS

## OUTPUTS

### PowerUp.UnquotedService

## NOTES

## RELATED LINKS

[https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/trusted_service_path.rb](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/trusted_service_path.rb)

