# Get-NetLocalGroupMember

## SYNOPSIS
Enumerates members of a specific local group on the local (or remote) machine.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect, Convert-ADName

## SYNTAX

```
Get-NetLocalGroupMember [[-ComputerName] <String[]>] [-GroupName <String>] [-Method <String>]
 [-Credential <PSCredential>]
```

## DESCRIPTION
This function will enumerate the members of a specified local group  on the
current, or remote, machine.
By default, the Win32 API call NetLocalGroupGetMembers
will be used (for speed).
Specifying "-Method WinNT" causes the WinNT service provider
to be used instead, which returns a larger amount of information.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-NetLocalGroupMember | ft
```

ComputerName   GroupName      MemberName     SID                   IsGroup       IsDomain
------------   ---------      ----------     ---                   -------       --------
WINDOWS1       Administrators WINDOWS1\Ad...
S-1-5-21-25... 
False          False
WINDOWS1       Administrators WINDOWS1\lo...
S-1-5-21-25... 
False          False
WINDOWS1       Administrators TESTLAB\Dom...
S-1-5-21-89... 
True           True
WINDOWS1       Administrators TESTLAB\har...
S-1-5-21-89... 
False           True

### -------------------------- EXAMPLE 2 --------------------------
```
Get-NetLocalGroupMember -Method winnt | ft
```

ComputerName   GroupName      MemberName     SID                   IsGroup       IsDomain
------------   ---------      ----------     ---                   -------       --------
WINDOWS1       Administrators WINDOWS1\Ad...
S-1-5-21-25... 
False          False
WINDOWS1       Administrators WINDOWS1\lo...
S-1-5-21-25... 
False          False
WINDOWS1       Administrators TESTLAB\Dom...
S-1-5-21-89... 
True           True
WINDOWS1       Administrators TESTLAB\har...
S-1-5-21-89... 
False           True

### -------------------------- EXAMPLE 3 --------------------------
```
Get-NetLocalGroup | Get-NetLocalGroupMember | ft
```

ComputerName   GroupName      MemberName     SID                   IsGroup       IsDomain
------------   ---------      ----------     ---                   -------       --------
WINDOWS1       Administrators WINDOWS1\Ad...
S-1-5-21-25... 
False          False
WINDOWS1       Administrators WINDOWS1\lo...
S-1-5-21-25... 
False          False
WINDOWS1       Administrators TESTLAB\Dom...
S-1-5-21-89... 
True           True
WINDOWS1       Administrators TESTLAB\har...
S-1-5-21-89... 
False           True
WINDOWS1       Guests         WINDOWS1\Guest S-1-5-21-25... 
False          False
WINDOWS1       IIS_IUSRS      NT AUTHORIT...
S-1-5-17                False          False
WINDOWS1       Users          NT AUTHORIT...
S-1-5-4                 False          False
WINDOWS1       Users          NT AUTHORIT...
S-1-5-11                False          False
WINDOWS1       Users          WINDOWS1\lo...
S-1-5-21-25... 
False        UNKNOWN
WINDOWS1       Users          TESTLAB\Dom...
S-1-5-21-89... 
True        UNKNOWN

### -------------------------- EXAMPLE 4 --------------------------
```
Get-NetLocalGroupMember -ComputerName primary.testlab.local | ft
```

ComputerName   GroupName      MemberName     SID                   IsGroup       IsDomain
------------   ---------      ----------     ---                   -------       --------
primary.tes...
Administrators TESTLAB\Adm...
S-1-5-21-89... 
False          False
primary.tes...
Administrators TESTLAB\loc...
S-1-5-21-89... 
False          False
primary.tes...
Administrators TESTLAB\Ent...
S-1-5-21-89... 
True          False
primary.tes...
Administrators TESTLAB\Dom...
S-1-5-21-89... 
True          False

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

### -GroupName
The local group name to query for users.
If not given, it defaults to "Administrators".

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: Administrators
Accept pipeline input: True (ByPropertyName)
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

### PowerView.LocalGroupMember.API

Custom PSObject with translated group property fields from API results.

PowerView.LocalGroupMember.WinNT

Custom PSObject with translated group property fields from WinNT results.

## NOTES

## RELATED LINKS

[http://stackoverflow.com/questions/21288220/get-all-local-members-and-groups-displayed-together
http://msdn.microsoft.com/en-us/library/aa772211(VS.85).aspx
https://msdn.microsoft.com/en-us/library/windows/desktop/aa370601(v=vs.85).aspx](http://stackoverflow.com/questions/21288220/get-all-local-members-and-groups-displayed-together
http://msdn.microsoft.com/en-us/library/aa772211(VS.85).aspx
https://msdn.microsoft.com/en-us/library/windows/desktop/aa370601(v=vs.85).aspx)

