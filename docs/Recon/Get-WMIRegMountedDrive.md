# Get-WMIRegMountedDrive

## SYNOPSIS
Returns information about saved network mounted drives for the local (or remote) machine.

Note: This function requires administrative rights on the machine you're enumerating.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: ConvertFrom-SID

## SYNTAX

```
Get-WMIRegMountedDrive [[-ComputerName] <String[]>] [-Credential <PSCredential>]
```

## DESCRIPTION
Uses remote registry functionality to enumerate recently mounted network drives.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-WMIRegMountedDrive
```

Returns the saved network mounted drives for the local machine.

### -------------------------- EXAMPLE 2 --------------------------
```
Get-WMIRegMountedDrive -ComputerName WINDOWS2.testlab.local
```

Returns the saved network mounted drives for the WINDOWS2.testlab.local machine

### -------------------------- EXAMPLE 3 --------------------------
```
Get-DomainComputer | Get-WMIRegMountedDrive
```

Returns the saved network mounted drives for all machines in the domain.

### -------------------------- EXAMPLE 4 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-WMIRegMountedDrive -ComputerName PRIMARY.testlab.local -Credential $Cred

## PARAMETERS

### -ComputerName
Specifies the hostname to query for mounted drive information (also accepts IP addresses).
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

### PowerView.RegMountedDrive

A PSCustomObject containing the ComputerName and mounted drive information.

## NOTES

## RELATED LINKS

