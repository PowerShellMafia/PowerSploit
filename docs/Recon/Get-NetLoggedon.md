# Get-NetLoggedon

## SYNOPSIS
Returns users logged on the local (or a remote) machine.
Note: administrative rights needed for newer Windows OSes.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect, Invoke-UserImpersonation, Invoke-RevertToSelf

## SYNTAX

```
Get-NetLoggedon [[-ComputerName] <String[]>] [-Credential <PSCredential>]
```

## DESCRIPTION
This function will execute the NetWkstaUserEnum Win32API call to query
a given host for actively logged on users.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-NetLoggedon
```

Returns users actively logged onto the local host.

### -------------------------- EXAMPLE 2 --------------------------
```
Get-NetLoggedon -ComputerName sqlserver
```

Returns users actively logged onto the 'sqlserver' host.

### -------------------------- EXAMPLE 3 --------------------------
```
Get-DomainComputer | Get-NetLoggedon
```

Returns all logged on users for all computers in the domain.

### -------------------------- EXAMPLE 4 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-NetLoggedon -ComputerName sqlserver -Credential $Cred

## PARAMETERS

### -ComputerName
Specifies the hostname to query for logged on users (also accepts IP addresses).
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

### PowerView.LoggedOnUserInfo

A PSCustomObject representing a WKSTA_USER_INFO_1 structure, including
the UserName/LogonDomain/AuthDomains/LogonServer for each user, with the ComputerName added.

## NOTES

## RELATED LINKS

[http://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/](http://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/)

