# Get-NetRDPSession

## SYNOPSIS
Returns remote desktop/session information for the local (or a remote) machine.

Note: only members of the Administrators or Account Operators local group
can successfully execute this functionality on a remote target.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect, Invoke-UserImpersonation, Invoke-RevertToSelf

## SYNTAX

```
Get-NetRDPSession [[-ComputerName] <String[]>] [-Credential <PSCredential>]
```

## DESCRIPTION
This function will execute the WTSEnumerateSessionsEx and WTSQuerySessionInformation
Win32API calls to query a given RDP remote service for active sessions and originating
IPs.
This is a replacement for qwinsta.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-NetRDPSession
```

Returns active RDP/terminal sessions on the local host.

### -------------------------- EXAMPLE 2 --------------------------
```
Get-NetRDPSession -ComputerName "sqlserver"
```

Returns active RDP/terminal sessions on the 'sqlserver' host.

### -------------------------- EXAMPLE 3 --------------------------
```
Get-DomainController | Get-NetRDPSession
```

Returns active RDP/terminal sessions on all domain controllers.

### -------------------------- EXAMPLE 4 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-NetRDPSession -ComputerName sqlserver -Credential $Cred

## PARAMETERS

### -ComputerName
Specifies the hostname to query for active sessions (also accepts IP addresses).
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

### PowerView.RDPSessionInfo

A PSCustomObject representing a combined WTS_SESSION_INFO_1 and WTS_CLIENT_ADDRESS structure,
with the ComputerName added.

## NOTES

## RELATED LINKS

[https://msdn.microsoft.com/en-us/library/aa383861(v=vs.85).aspx](https://msdn.microsoft.com/en-us/library/aa383861(v=vs.85).aspx)

