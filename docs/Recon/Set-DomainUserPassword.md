# Set-DomainUserPassword

## SYNOPSIS
Sets the password for a given user identity.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-PrincipalContext

## SYNTAX

```
Set-DomainUserPassword [-Identity] <String> -AccountPassword <SecureString> [-Domain <String>]
 [-Credential <PSCredential>]
```

## DESCRIPTION
First binds to the specified domain context using Get-PrincipalContext.
The bound domain context is then used to search for the specified user -Identity,
which returns a DirectoryServices.AccountManagement.UserPrincipal object.
The
SetPassword() function is then invoked on the user, setting the password to -AccountPassword.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

Set-DomainUserPassword -Identity andy -AccountPassword $UserPassword

Resets the password for 'andy' to the password specified.

### -------------------------- EXAMPLE 2 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
Set-DomainUserPassword -Identity andy -AccountPassword $UserPassword -Credential $Cred

Resets the password for 'andy' usering the alternate credentials specified.

## PARAMETERS

### -Identity
A user SamAccountName (e.g.
User1), DistinguishedName (e.g.
CN=user1,CN=Users,DC=testlab,DC=local),
SID (e.g.
S-1-5-21-890171859-3433809279-3366196753-1113), or GUID (e.g.
4c435dd7-dc58-4b14-9a5e-1fdb0e80d201)
specifying the user to reset the password for.

```yaml
Type: String
Parameter Sets: (All)
Aliases: UserName, UserIdentity, User

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -AccountPassword
Specifies the password to reset the target user's to.
Mandatory.

```yaml
Type: SecureString
Parameter Sets: (All)
Aliases: Password

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Domain
Specifies the domain to use to search for the user identity, defaults to the current domain.

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

### DirectoryServices.AccountManagement.UserPrincipal

## NOTES

## RELATED LINKS

[http://richardspowershellblog.wordpress.com/2008/05/25/system-directoryservices-accountmanagement/](http://richardspowershellblog.wordpress.com/2008/05/25/system-directoryservices-accountmanagement/)

