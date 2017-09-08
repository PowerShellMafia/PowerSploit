# Get-DomainGPOComputerLocalGroupMapping

## SYNOPSIS
Takes a computer (or GPO) object and determines what users/groups are in the specified
local group for the machine through GPO correlation.

Author: @harmj0y  
License: BSD 3-Clause  
Required Dependencies: Get-DomainComputer, Get-DomainOU, Get-NetComputerSiteName, Get-DomainSite, Get-DomainGPOLocalGroup

## SYNTAX

### ComputerIdentity (Default)
```
Get-DomainGPOComputerLocalGroupMapping [-ComputerIdentity] <String> [-LocalGroup <String>] [-Domain <String>]
 [-SearchBase <String>] [-Server <String>] [-SearchScope <String>] [-ResultPageSize <Int32>]
 [-ServerTimeLimit <Int32>] [-Tombstone] [-Credential <PSCredential>]
```

### OUIdentity
```
Get-DomainGPOComputerLocalGroupMapping -OUIdentity <String> [-LocalGroup <String>] [-Domain <String>]
 [-SearchBase <String>] [-Server <String>] [-SearchScope <String>] [-ResultPageSize <Int32>]
 [-ServerTimeLimit <Int32>] [-Tombstone] [-Credential <PSCredential>]
```

## DESCRIPTION
This function is the inverse of Get-DomainGPOUserLocalGroupMapping, and finds what users/groups
are in the specified local group for a target machine through GPO correlation.

If a -ComputerIdentity is specified, retrieve the complete computer object, attempt to
determine the OU the computer is a part of.
Then resolve the computer's site name with
Get-NetComputerSiteName and retrieve all sites object Get-DomainSite.
For those results, attempt to
enumerate all linked GPOs and associated local group settings with Get-DomainGPOLocalGroup.
For
each resulting GPO group, resolve the resulting user/group name to a full AD object and
return the results.
This will return the domain objects that are members of the specified
-LocalGroup for the given computer.

Otherwise, if -OUIdentity is supplied, the same process is executed to find linked GPOs and
localgroup specifications.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-DomainGPOComputerLocalGroupMapping -ComputerName WINDOWS3.testlab.local
```

Finds users who have local admin rights over WINDOWS3 through GPO correlation.

### -------------------------- EXAMPLE 2 --------------------------
```
Get-DomainGPOComputerLocalGroupMapping -Domain dev.testlab.local -ComputerName WINDOWS4.dev.testlab.local -LocalGroup RDP
```

Finds users who have RDP rights over WINDOWS4 through GPO correlation.

### -------------------------- EXAMPLE 3 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainGPOComputerLocalGroupMapping -Credential $Cred -ComputerIdentity SQL.testlab.local

## PARAMETERS

### -ComputerIdentity
A SamAccountName (e.g.
WINDOWS10$), DistinguishedName (e.g.
CN=WINDOWS10,CN=Computers,DC=testlab,DC=local),
SID (e.g.
S-1-5-21-890171859-3433809279-3366196753-1124), GUID (e.g.
4f16b6bc-7010-4cbf-b628-f3cfe20f6994),
or a dns host name (e.g.
windows10.testlab.local) for the computer to identity GPO local group mappings for.

```yaml
Type: String
Parameter Sets: ComputerIdentity
Aliases: ComputerName, Computer, DistinguishedName, SamAccountName, Name

Required: True
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -OUIdentity
An OU name (e.g.
TestOU), DistinguishedName (e.g.
OU=TestOU,DC=testlab,DC=local), or
GUID (e.g.
8a9ba22a-8977-47e6-84ce-8c26af4e1e6a) for the OU to identity GPO local group mappings for.

```yaml
Type: String
Parameter Sets: OUIdentity
Aliases: OU

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -LocalGroup
The local group to check access against.
Can be "Administrators" (S-1-5-32-544), "RDP/Remote Desktop Users" (S-1-5-32-555),
or a custom local SID.
Defaults to local 'Administrators'.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: Administrators
Accept pipeline input: False
Accept wildcard characters: False
```

### -Domain
Specifies the domain to enumerate GPOs for, defaults to the current domain.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SearchBase
{{Fill SearchBase Description}}

```yaml
Type: String
Parameter Sets: (All)
Aliases: ADSPath

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Server
Specifies an Active Directory server (domain controller) to bind to.

```yaml
Type: String
Parameter Sets: (All)
Aliases: DomainController

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SearchScope
Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: Subtree
Accept pipeline input: False
Accept wildcard characters: False
```

### -ResultPageSize
Specifies the PageSize to set for the LDAP searcher object.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: 200
Accept pipeline input: False
Accept wildcard characters: False
```

### -ServerTimeLimit
Specifies the maximum amount of time the server spends searching.
Default of 120 seconds.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: 0
Accept pipeline input: False
Accept wildcard characters: False
```

### -Tombstone
Switch.
Specifies that the searcher should also return deleted/tombstoned objects.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -Credential
A \[Management.Automation.PSCredential\] object of alternate credentials
for connection to the target domain.

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

### PowerView.GGPOComputerLocalGroupMember

## NOTES

## RELATED LINKS

