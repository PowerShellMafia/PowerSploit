# Find-InterestingFile

## SYNOPSIS
Searches for files on the given path that match a series of specified criteria.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Add-RemoteConnection, Remove-RemoteConnection

## SYNTAX

### FileSpecification (Default)
```
Find-InterestingFile [[-Path] <String[]>] [-Include <String[]>] [-LastAccessTime <DateTime>]
 [-LastWriteTime <DateTime>] [-CreationTime <DateTime>] [-ExcludeFolders] [-ExcludeHidden] [-CheckWriteAccess]
 [-Credential <PSCredential>]
```

### OfficeDocs
```
Find-InterestingFile [[-Path] <String[]>] [-OfficeDocs] [-CheckWriteAccess] [-Credential <PSCredential>]
```

### FreshEXEs
```
Find-InterestingFile [[-Path] <String[]>] [-FreshEXEs] [-CheckWriteAccess] [-Credential <PSCredential>]
```

## DESCRIPTION
This function recursively searches a given UNC path for files with
specific keywords in the name (default of pass, sensitive, secret, admin,
login and unattend*.xml).
By default, hidden files/folders are included
in search results.
If -Credential is passed, Add-RemoteConnection/Remove-RemoteConnection
is used to temporarily map the remote share.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Find-InterestingFile -Path "C:\Backup\"
```

Returns any files on the local path C:\Backup\ that have the default
search term set in the title.

### -------------------------- EXAMPLE 2 --------------------------
```
Find-InterestingFile -Path "\\WINDOWS7\Users\" -LastAccessTime (Get-Date).AddDays(-7)
```

Returns any files on the remote path \\\\WINDOWS7\Users\ that have the default
search term set in the title and were accessed within the last week.

### -------------------------- EXAMPLE 3 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Find-InterestingFile -Credential $Cred -Path "\\\\PRIMARY.testlab.local\C$\Temp\"

## PARAMETERS

### -Path
UNC/local path to recursively search.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases: 

Required: False
Position: 1
Default value: .\
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -Include
Only return files/folders that match the specified array of strings,
i.e.
@(*.doc*, *.xls*, *.ppt*)

```yaml
Type: String[]
Parameter Sets: FileSpecification
Aliases: SearchTerms, Terms

Required: False
Position: Named
Default value: @('*password*', '*sensitive*', '*admin*', '*login*', '*secret*', 'unattend*.xml', '*.vmdk', '*creds*', '*credential*', '*.config')
Accept pipeline input: False
Accept wildcard characters: False
```

### -LastAccessTime
Only return files with a LastAccessTime greater than this date value.

```yaml
Type: DateTime
Parameter Sets: FileSpecification
Aliases: 

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -LastWriteTime
Only return files with a LastWriteTime greater than this date value.

```yaml
Type: DateTime
Parameter Sets: FileSpecification
Aliases: 

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -CreationTime
Only return files with a CreationTime greater than this date value.

```yaml
Type: DateTime
Parameter Sets: FileSpecification
Aliases: 

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -OfficeDocs
Switch.
Search for office documents (*.doc*, *.xls*, *.ppt*)

```yaml
Type: SwitchParameter
Parameter Sets: OfficeDocs
Aliases: 

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -FreshEXEs
Switch.
Find .EXEs accessed within the last 7 days.

```yaml
Type: SwitchParameter
Parameter Sets: FreshEXEs
Aliases: 

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExcludeFolders
Switch.
Exclude folders from the search results.

```yaml
Type: SwitchParameter
Parameter Sets: FileSpecification
Aliases: 

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExcludeHidden
Switch.
Exclude hidden files and folders from the search results.

```yaml
Type: SwitchParameter
Parameter Sets: FileSpecification
Aliases: 

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -CheckWriteAccess
Switch.
Only returns files the current user has write access to.

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
to connect to remote systems for file enumeration.

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

### PowerView.FoundFile

## NOTES

## RELATED LINKS

