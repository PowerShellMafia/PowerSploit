# Test-AdminAccess

## SYNOPSIS
Tests if the current user has administrative access to the local (or a remote) machine.

Idea stolen from the local_admin_search_enum post module in Metasploit written by:  
    'Brandon McCann "zeknox" \<bmccann\[at\]accuvant.com\>'  
    'Thomas McCarthy "smilingraccoon" \<smilingraccoon\[at\]gmail.com\>'  
    'Royce Davis "r3dy" \<rdavis\[at\]accuvant.com\>'  

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect, Invoke-UserImpersonation, Invoke-RevertToSelf

## SYNTAX

```
Test-AdminAccess [[-ComputerName] <String[]>] [-Credential <PSCredential>]
```

## DESCRIPTION
This function will use the OpenSCManagerW Win32API call to establish
a handle to the remote host.
If this succeeds, the current user context
has local administrator acess to the target.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Test-AdminAccess -ComputerName sqlserver
```

Returns results indicating whether the current user has admin access to the 'sqlserver' host.

### -------------------------- EXAMPLE 2 --------------------------
```
Get-DomainComputer | Test-AdminAccess
```

Returns what machines in the domain the current user has access to.

### -------------------------- EXAMPLE 3 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Test-AdminAccess -ComputerName sqlserver -Credential $Cred

## PARAMETERS

### -ComputerName
Specifies the hostname to check for local admin access (also accepts IP addresses).
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

### PowerView.AdminAccess

A PSCustomObject containing the ComputerName and 'IsAdmin' set to whether
the current user has local admin rights, along with the ComputerName added.

## NOTES

## RELATED LINKS

[https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/local_admin_search_enum.rb
http://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/local_admin_search_enum.rb
http://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/)

