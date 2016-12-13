# Get-PathAcl

## SYNOPSIS
Enumerates the ACL for a given file path.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Add-RemoteConnection, Remove-RemoteConnection, ConvertFrom-SID

## SYNTAX

```
Get-PathAcl [-Path] <String[]> [[-Credential] <PSCredential>]
```

## DESCRIPTION
Enumerates the ACL for a specified file/folder path, and translates
the access rules for each entry into readable formats.
If -Credential is passed,
Add-RemoteConnection/Remove-RemoteConnection is used to temporarily map the remote share.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-PathAcl "\\SERVER\Share\"
```

Returns ACLs for the given UNC share.

### -------------------------- EXAMPLE 2 --------------------------
```
gci .\test.txt | Get-PathAcl
```

### -------------------------- EXAMPLE 3 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm', $SecPassword)
Get-PathAcl -Path "\\\\SERVER\Share\" -Credential $Cred

## PARAMETERS

### -Path
Specifies the local or remote path to enumerate the ACLs for.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases: FullName

Required: True
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -Credential
A \[Management.Automation.PSCredential\] object of alternate credentials
for connection to the target path.

```yaml
Type: PSCredential
Parameter Sets: (All)
Aliases: 

Required: False
Position: 2
Default value: [Management.Automation.PSCredential]::Empty
Accept pipeline input: False
Accept wildcard characters: False
```

## INPUTS

### String

One of more paths to enumerate ACLs for.

## OUTPUTS

### PowerView.FileACL

A custom object with the full path and associated ACL entries.

## NOTES

## RELATED LINKS

[https://support.microsoft.com/en-us/kb/305144](https://support.microsoft.com/en-us/kb/305144)

