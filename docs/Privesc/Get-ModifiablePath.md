# Get-ModifiablePath

## SYNOPSIS
Parses a passed string containing multiple possible file/folder paths and returns
the file paths where the current user has modification rights.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None

## SYNTAX

```
Get-ModifiablePath [-Path] <String[]> [-Literal]
```

## DESCRIPTION
Takes a complex path specification of an initial file/folder path with possible
configuration files, 'tokenizes' the string in a number of possible ways, and
enumerates the ACLs for each path that currently exists on the system.
Any path that
the current user has modification rights on is returned in a custom object that contains
the modifiable path, associated permission set, and the IdentityReference with the specified
rights.
The SID of the current user and any group he/she are a part of are used as the
comparison set against the parsed path DACLs.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
'"C:\Temp\blah.exe" -f "C:\Temp\config.ini"' | Get-ModifiablePath
```

Path                       Permissions                IdentityReference
----                       -----------                -----------------
C:\Temp\blah.exe           {ReadAttributes, ReadCo...
NT AUTHORITY\Authentic...
C:\Temp\config.ini         {ReadAttributes, ReadCo...
NT AUTHORITY\Authentic...

### -------------------------- EXAMPLE 2 --------------------------
```
Get-ChildItem C:\Vuln\ -Recurse | Get-ModifiablePath
```

Path                       Permissions                IdentityReference
----                       -----------                -----------------
C:\Vuln\blah.bat           {ReadAttributes, ReadCo...
NT AUTHORITY\Authentic...
C:\Vuln\config.ini         {ReadAttributes, ReadCo...
NT AUTHORITY\Authentic...
...

## PARAMETERS

### -Path
The string path to parse for modifiable files.
Required

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

### -Literal
Switch.
Treat all paths as literal (i.e.
don't do 'tokenization').

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: LiteralPaths

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

## INPUTS

## OUTPUTS

### PowerUp.TokenPrivilege.ModifiablePath

Custom PSObject containing the Permissions, ModifiablePath, IdentityReference for
a modifiable path.

## NOTES

## RELATED LINKS

