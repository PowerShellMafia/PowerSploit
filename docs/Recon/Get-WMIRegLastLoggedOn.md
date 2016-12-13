# Get-WMIRegLastLoggedOn

## SYNOPSIS
Returns the last user who logged onto the local (or a remote) machine.

Note: This function requires administrative rights on the machine you're enumerating.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None

## SYNTAX

```
Get-WMIRegLastLoggedOn [[-ComputerName] <String[]>] [-Credential <PSCredential>]
```

## DESCRIPTION
This function uses remote registry to enumerate the LastLoggedOnUser registry key
for the local (or remote) machine.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-WMIRegLastLoggedOn
```

Returns the last user logged onto the local machine.

### -------------------------- EXAMPLE 2 --------------------------
```
Get-WMIRegLastLoggedOn -ComputerName WINDOWS1
```

Returns the last user logged onto WINDOWS1

### -------------------------- EXAMPLE 3 --------------------------
```
Get-DomainComputer | Get-WMIRegLastLoggedOn
```

Returns the last user logged onto all machines in the domain.

### -------------------------- EXAMPLE 4 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-WMIRegLastLoggedOn -ComputerName PRIMARY.testlab.local -Credential $Cred

## PARAMETERS

### -ComputerName
Specifies the hostname to query for remote registry values (also accepts IP addresses).
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

### PowerView.LastLoggedOnUser

A PSCustomObject containing the ComputerName and last loggedon user.

## NOTES

## RELATED LINKS

