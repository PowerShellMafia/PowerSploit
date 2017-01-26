# Get-WMIRegCachedRDPConnection

## SYNOPSIS
Returns information about RDP connections outgoing from the local (or remote) machine.

Note: This function requires administrative rights on the machine you're enumerating.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: ConvertFrom-SID

## SYNTAX

```
Get-WMIRegCachedRDPConnection [[-ComputerName] <String[]>] [-Credential <PSCredential>]
```

## DESCRIPTION
Uses remote registry functionality to query all entries for the
"Windows Remote Desktop Connection Client" on a machine, separated by
user and target server.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-WMIRegCachedRDPConnection
```

Returns the RDP connection client information for the local machine.

### -------------------------- EXAMPLE 2 --------------------------
```
Get-WMIRegCachedRDPConnection  -ComputerName WINDOWS2.testlab.local
```

Returns the RDP connection client information for the WINDOWS2.testlab.local machine

### -------------------------- EXAMPLE 3 --------------------------
```
Get-DomainComputer | Get-WMIRegCachedRDPConnection
```

Returns cached RDP information for all machines in the domain.

### -------------------------- EXAMPLE 4 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-WMIRegCachedRDPConnection -ComputerName PRIMARY.testlab.local -Credential $Cred

## PARAMETERS

### -ComputerName
Specifies the hostname to query for cached RDP connections (also accepts IP addresses).
Defaults to 'localhost'.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases: HostName, dnshostname, name

Required: False
Position: 1
Default value: Localhost
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -Credential
A \[Management.Automation.PSCredential\] object of alternate credentials
for connecting to the remote system.

```yaml
Type: PSCredential
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: [Management.Automation.PSCredential]::Empty
Accept pipeline input: False
Accept wildcard characters: False
```

## INPUTS

## OUTPUTS

### PowerView.CachedRDPConnection

A PSCustomObject containing the ComputerName and cached RDP information.

## NOTES

## RELATED LINKS

