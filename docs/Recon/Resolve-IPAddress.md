# Resolve-IPAddress

## SYNOPSIS
Resolves a given hostename to its associated IPv4 address.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None

## SYNTAX

```
Resolve-IPAddress [[-ComputerName] <String[]>]
```

## DESCRIPTION
Resolves a given hostename to its associated IPv4 address using
\[Net.Dns\]::GetHostEntry().
If no hostname is provided, the default
is the IP address of the localhost.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Resolve-IPAddress -ComputerName SERVER
```

### -------------------------- EXAMPLE 2 --------------------------
```
@("SERVER1", "SERVER2") | Resolve-IPAddress
```

## PARAMETERS

### -ComputerName
{{Fill ComputerName Description}}

```yaml
Type: String[]
Parameter Sets: (All)
Aliases: HostName, dnshostname, name

Required: False
Position: 1
Default value: $Env:COMPUTERNAME
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

## INPUTS

### String

Accepts one or more IP address strings on the pipeline.

## OUTPUTS

### System.Management.Automation.PSCustomObject

A custom PSObject with the ComputerName and IPAddress.

## NOTES

## RELATED LINKS

