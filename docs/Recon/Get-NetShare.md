# Get-NetShare

## SYNOPSIS
Returns open shares on the local (or a remote) machine.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect, Invoke-UserImpersonation, Invoke-RevertToSelf

## SYNTAX

```
Get-NetShare [[-ComputerName] <String[]>] [-Credential <PSCredential>]
```

## DESCRIPTION
This function will execute the NetShareEnum Win32API call to query
a given host for open shares.
This is a replacement for "net share \\\\hostname".

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-NetShare
```

Returns active shares on the local host.

### -------------------------- EXAMPLE 2 --------------------------
```
Get-NetShare -ComputerName sqlserver
```

Returns active shares on the 'sqlserver' host

### -------------------------- EXAMPLE 3 --------------------------
```
Get-DomainComputer | Get-NetShare
```

Returns all shares for all computers in the domain.

### -------------------------- EXAMPLE 4 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-NetShare -ComputerName sqlserver -Credential $Cred

## PARAMETERS

### -ComputerName
Specifies the hostname to query for shares (also accepts IP addresses).
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
for connection to the remote system using Invoke-UserImpersonation.

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

### PowerView.ShareInfo

A PSCustomObject representing a SHARE_INFO_1 structure, including
the name/type/remark for each share, with the ComputerName added.

## NOTES

## RELATED LINKS

[http://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/](http://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/)

