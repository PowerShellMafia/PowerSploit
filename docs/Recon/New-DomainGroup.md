# New-DomainGroup

## SYNOPSIS
Creates a new domain group (assuming appropriate permissions) and returns the group object.

TODO: implement all properties that New-ADGroup implements (https://technet.microsoft.com/en-us/library/ee617253.aspx).

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-PrincipalContext

## SYNTAX

```
New-DomainGroup [-SamAccountName] <String> [[-Name] <String>] [[-DisplayName] <String>]
 [[-Description] <String>] [[-Domain] <String>] [[-Credential] <PSCredential>]
```

## DESCRIPTION
First binds to the specified domain context using Get-PrincipalContext.
The bound domain context is then used to create a new
DirectoryServices.AccountManagement.GroupPrincipal with the specified
group properties.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
New-DomainGroup -SamAccountName TestGroup -Description 'This is a test group.'
```

Creates the 'TestGroup' group with the specified description.

### -------------------------- EXAMPLE 2 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
New-DomainGroup -SamAccountName TestGroup -Description 'This is a test group.' -Credential $Cred

Creates the 'TestGroup' group with the specified description using the specified alternate credentials.

## PARAMETERS

### -SamAccountName
Specifies the Security Account Manager (SAM) account name of the group to create.
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

### -Name
Specifies the name of the group to create.
If not provided, defaults to SamAccountName.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DisplayName
Specifies the display name of the group to create.
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

### -Description
Specifies the description of the group to create.

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

### -Domain
Specifies the domain to use to search for user/group principals, defaults to the current domain.

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

### -Credential
A \[Management.Automation.PSCredential\] object of alternate credentials
for connection to the target domain.

```yaml
Type: PSCredential
Parameter Sets: (All)
Aliases: 

Required: False
Position: 6
Default value: [Management.Automation.PSCredential]::Empty
Accept pipeline input: False
Accept wildcard characters: False
```

## INPUTS

## OUTPUTS

### DirectoryServices.AccountManagement.GroupPrincipal

## NOTES

## RELATED LINKS

