# Get-WMIProcess

## SYNOPSIS
Returns a list of processes and their owners on the local or remote machine.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None

## SYNTAX

```
Get-WMIProcess [[-ComputerName] <String[]>] [-Credential <PSCredential>]
```

## DESCRIPTION
Uses Get-WMIObject to enumerate all Win32_process instances on the local or remote machine,
including the owners of the particular process.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-WMIProcess -ComputerName WINDOWS1
```

### -------------------------- EXAMPLE 2 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-WMIProcess -ComputerName PRIMARY.testlab.local -Credential $Cred

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
for connection to the remote system.

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

### PowerView.UserProcess

A PSCustomObject containing the remote process information.

## NOTES

## RELATED LINKS

