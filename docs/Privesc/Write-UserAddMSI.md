# Write-UserAddMSI

## SYNOPSIS
Writes out a precompiled MSI installer that prompts for a user/group addition.
This function can be used to abuse Get-RegistryAlwaysInstallElevated.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None

## SYNTAX

```
Write-UserAddMSI [[-Path] <String>]
```

## DESCRIPTION
Writes out a precompiled MSI installer that prompts for a user/group addition.
This function can be used to abuse Get-RegistryAlwaysInstallElevated.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Write-UserAddMSI
```

Writes the user add MSI to the local directory.

## PARAMETERS

### -Path
{{Fill Path Description}}

```yaml
Type: String
Parameter Sets: (All)
Aliases: ServiceName

Required: False
Position: 1
Default value: UserAdd.msi
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

## INPUTS

## OUTPUTS

### PowerUp.UserAddMSI

## NOTES

## RELATED LINKS

