# New-DomainUser

## SYNOPSIS
Creates a new domain user (assuming appropriate permissions) and returns the user object.

TODO: implement all properties that New-ADUser implements (https://technet.microsoft.com/en-us/library/ee617253.aspx).

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-PrincipalContext

## SYNTAX

```
New-DomainUser [-SamAccountName] <String> [-AccountPassword] <SecureString> [[-Name] <String>]
 [[-DisplayName] <String>] [[-Description] <String>] [[-Domain] <String>] [[-Credential] <PSCredential>]
```

## DESCRIPTION
First binds to the specified domain context using Get-PrincipalContext.
The bound domain context is then used to create a new
DirectoryServices.AccountManagement.UserPrincipal with the specified user properties.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

New-DomainUser -SamAccountName harmj0y2 -Description 'This is harmj0y' -AccountPassword $UserPassword

Creates the 'harmj0y2' user with the specified description and password.

### -------------------------- EXAMPLE 2 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$user = New-DomainUser -SamAccountName harmj0y2 -Description 'This is harmj0y' -AccountPassword $UserPassword -Credential $Cred

Creates the 'harmj0y2' user with the specified description and password, using the specified
alternate credentials.

### -------------------------- EXAMPLE 3 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
New-DomainUser -SamAccountName andy -AccountPassword $UserPassword -Credential $Cred | Add-DomainGroupMember 'Domain Admins' -Credential $Cred

Creates the 'andy' user with the specified description and password, using the specified
alternate credentials, and adds the user to 'domain admins' using Add-DomainGroupMember
and the alternate credentials.

## PARAMETERS

### -SamAccountName
Specifies the Security Account Manager (SAM) account name of the user to create.
Maximum of 256 characters.
Mandatory.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -AccountPassword
Specifies the password for the created user.
Mandatory.

```yaml
Type: SecureString
Parameter Sets: (All)
Aliases: Password

Required: True
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Name
Specifies the name of the user to create.
If not provided, defaults to SamAccountName.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: 3
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DisplayName
Specifies the display name of the user to create.
If not provided, defaults to SamAccountName.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: 4
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Description
Specifies the description of the user to create.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: 5
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Domain
Specifies the domain to use to search for user/group principals, defaults to the current domain.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: 6
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
Position: 7
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

