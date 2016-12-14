# Get-RegistryAutoLogon

## SYNOPSIS
Finds any autologon credentials left in the registry.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None

## SYNTAX

```
Get-RegistryAutoLogon
```

## DESCRIPTION
Checks if any autologon accounts/credentials are set in a number of registry locations.
If they are, the credentials are extracted and returned as a custom PSObject.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-RegistryAutoLogon
```

Finds any autologon credentials left in the registry.

## PARAMETERS

## INPUTS

## OUTPUTS

### PowerUp.RegistryAutoLogon

Custom PSObject containing autologin credentials found in the registry.

## NOTES

## RELATED LINKS

[https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/windows_autologin.rb](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/windows_autologin.rb)

