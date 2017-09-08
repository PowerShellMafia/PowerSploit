# Get-DomainFileServer

## SYNOPSIS
Returns a list of servers likely functioning as file servers.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher

## SYNTAX

```
Get-DomainFileServer [[-Domain] <String[]>] [[-LDAPFilter] <String>] [[-SearchBase] <String>]
 [[-Server] <String>] [[-SearchScope] <String>] [[-ResultPageSize] <Int32>] [[-ServerTimeLimit] <Int32>]
 [-Tombstone] [[-Credential] <PSCredential>]
```

## DESCRIPTION
Returns a list of likely fileservers by searching for all users in Active Directory
with non-null homedirectory, scriptpath, or profilepath fields, and extracting/uniquifying
the server names.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-DomainFileServer
```

Returns active file servers for the current domain.

### -------------------------- EXAMPLE 2 --------------------------
```
Get-DomainFileServer -Domain testing.local
```

Returns active file servers for the 'testing.local' domain.

### -------------------------- EXAMPLE 3 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainFileServer -Credential $Cred

## PARAMETERS

### -Domain
Specifies the domain to use for the query, defaults to the current domain.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases: DomainName, Name

Required: False
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -LDAPFilter
Specifies an LDAP query string that is used to filter Active Directory objects.

```yaml
Type: String
Parameter Sets: (All)
Aliases: Filter

Required: False
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SearchBase
The LDAP source to search through, e.g.
"LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

```yaml
Type: String
Parameter Sets: (All)
Aliases: ADSPath

Required: False
Position: 3
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
Position: 4
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
Position: 5
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
Position: 6
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
Position: 7
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
Position: 8
Default value: [Management.Automation.PSCredential]::Empty
Accept pipeline input: False
Accept wildcard characters: False
```

## INPUTS

## OUTPUTS

### String

One or more strings representing file server names.

## NOTES

## RELATED LINKS

