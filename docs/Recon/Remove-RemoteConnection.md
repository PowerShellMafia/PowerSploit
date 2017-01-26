# Remove-RemoteConnection

## SYNOPSIS
Destroys a connection created by New-RemoteConnection.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect

## SYNTAX

### ComputerName (Default)
```
Remove-RemoteConnection [-ComputerName] <String[]>
```

### Path
```
Remove-RemoteConnection [-Path] <String[]>
```

## DESCRIPTION
This function uses WNetCancelConnection2 to destroy a connection created by
New-RemoteConnection.
If a -Path isn't specified, a -ComputerName is required to
'unmount' \\\\$ComputerName\IPC$.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Remove-RemoteConnection -ComputerName 'PRIMARY.testlab.local'
```

### -------------------------- EXAMPLE 2 --------------------------
```
Remove-RemoteConnection -Path '\\PRIMARY.testlab.local\C$\'
```

### -------------------------- EXAMPLE 3 --------------------------
```
@('PRIMARY.testlab.local','SECONDARY.testlab.local') | Remove-RemoteConnection
```

## PARAMETERS

### -ComputerName
Specifies the system to remove a \\\\ComputerName\IPC$ connection for.

```yaml
Type: String[]
Parameter Sets: ComputerName
Aliases: HostName, dnshostname, name

Required: True
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -Path
Specifies the remote \\\\UNC\path to remove the connection for.

```yaml
Type: String[]
Parameter Sets: Path
Aliases: 

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS

