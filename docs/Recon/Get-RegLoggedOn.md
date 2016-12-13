# Get-RegLoggedOn

## SYNOPSIS
Returns who is logged onto the local (or a remote) machine
through enumeration of remote registry keys.

Note: This function requires only domain user rights on the
machine you're enumerating, but remote registry must be enabled.

Author: Matt Kelly (@BreakersAll)  
License: BSD 3-Clause  
Required Dependencies: Invoke-UserImpersonation, Invoke-RevertToSelf, ConvertFrom-SID

## SYNTAX

```
Get-RegLoggedOn [[-ComputerName] <String[]>]
```

## DESCRIPTION
This function will query the HKU registry values to retrieve the local
logged on users SID and then attempt and reverse it.
Adapted technique from Sysinternal's PSLoggedOn script.
Benefit over
using the NetWkstaUserEnum API (Get-NetLoggedon) of less user privileges
required (NetWkstaUserEnum requires remote admin access).

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-RegLoggedOn
```

Returns users actively logged onto the local host.

### -------------------------- EXAMPLE 2 --------------------------
```
Get-RegLoggedOn -ComputerName sqlserver
```

Returns users actively logged onto the 'sqlserver' host.

### -------------------------- EXAMPLE 3 --------------------------
```
Get-DomainController | Get-RegLoggedOn
```

Returns users actively logged on all domain controllers.

### -------------------------- EXAMPLE 4 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-RegLoggedOn -ComputerName sqlserver -Credential $Cred

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

## INPUTS

## OUTPUTS

### PowerView.RegLoggedOnUser

A PSCustomObject including the UserDomain/UserName/UserSID of each
actively logged on user, with the ComputerName added.

## NOTES

## RELATED LINKS

