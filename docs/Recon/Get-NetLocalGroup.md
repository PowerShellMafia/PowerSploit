# Get-NetLocalGroup

## SYNOPSIS
Enumerates the local groups on the local (or remote) machine.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect

## SYNTAX

```
Get-NetLocalGroup [[-ComputerName] <String[]>] [-Method <String>] [-Credential <PSCredential>]
```

## DESCRIPTION
This function will enumerate the names and descriptions for the
local groups on the current, or remote, machine.
By default, the Win32 API
call NetLocalGroupEnum will be used (for speed).
Specifying "-Method WinNT"
causes the WinNT service provider to be used instead, which returns group
SIDs along with the group names and descriptions/comments.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-NetLocalGroup
```

ComputerName                  GroupName                     Comment
------------                  ---------                     -------
WINDOWS1                      Administrators                Administrators have comple...
WINDOWS1                      Backup Operators              Backup Operators can overr...
WINDOWS1                      Cryptographic Operators       Members are authorized to ...
...

### -------------------------- EXAMPLE 2 --------------------------
```
Get-NetLocalGroup -Method Winnt
```

ComputerName           GroupName              GroupSID              Comment
------------           ---------              --------              -------
WINDOWS1               Administrators         S-1-5-32-544          Administrators hav...
WINDOWS1               Backup Operators       S-1-5-32-551          Backup Operators c...
WINDOWS1               Cryptographic Opera...
S-1-5-32-569          Members are author...
...

### -------------------------- EXAMPLE 3 --------------------------
```
Get-NetLocalGroup -ComputerName primary.testlab.local
```

ComputerName                  GroupName                     Comment
------------                  ---------                     -------
primary.testlab.local         Administrators                Administrators have comple...
primary.testlab.local         Users                         Users are prevented from m...
primary.testlab.local         Guests                        Guests have the same acces...
primary.testlab.local         Print Operators               Members can administer dom...
primary.testlab.local         Backup Operators              Backup Operators can overr...

## PARAMETERS

### -ComputerName
Specifies the hostname to query for sessions (also accepts IP addresses).
Defaults to the localhost.

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

### -Method
The collection method to use, defaults to 'API', also accepts 'WinNT'.

```yaml
Type: String
Parameter Sets: (All)
Aliases: CollectionMethod

Required: False
Position: Named
Default value: API
Accept pipeline input: False
Accept wildcard characters: False
```

### -Credential
A \[Management.Automation.PSCredential\] object of alternate credentials
for connection to a remote machine.
Only applicable with "-Method WinNT".

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

### PowerView.LocalGroup.API

Custom PSObject with translated group property fields from API results.

PowerView.LocalGroup.WinNT

Custom PSObject with translated group property fields from WinNT results.

## NOTES

## RELATED LINKS

[https://msdn.microsoft.com/en-us/library/windows/desktop/aa370440(v=vs.85).aspx](https://msdn.microsoft.com/en-us/library/windows/desktop/aa370440(v=vs.85).aspx)

