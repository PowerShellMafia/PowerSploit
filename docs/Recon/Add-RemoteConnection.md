# Add-RemoteConnection

## SYNOPSIS
Pseudo "mounts" a connection to a remote path using the specified
credential object, allowing for access of remote resources.
If a -Path isn't
specified, a -ComputerName is required to pseudo-mount IPC$.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect

## SYNTAX

### ComputerName (Default)
```
Add-RemoteConnection [-ComputerName] <String[]> -Credential <PSCredential>
```

### Path
```
Add-RemoteConnection [-Path] <String[]> -Credential <PSCredential>
```

## DESCRIPTION
This function uses WNetAddConnection2W to make a 'temporary' (i.e.
not saved) connection
to the specified remote -Path (\\\\UNC\share) with the alternate credentials specified in the
-Credential object.
If a -Path isn't specified, a -ComputerName is required to pseudo-mount IPC$.

To destroy the connection, use Remove-RemoteConnection with the same specified \\\\UNC\share path
or -ComputerName.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
$Cred = Get-Credential
```

Add-RemoteConnection -ComputerName 'PRIMARY.testlab.local' -Credential $Cred

### -------------------------- EXAMPLE 2 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Add-RemoteConnection -Path '\\\\PRIMARY.testlab.local\C$\' -Credential $Cred

### -------------------------- EXAMPLE 3 --------------------------
```
$Cred = Get-Credential
```

@('PRIMARY.testlab.local','SECONDARY.testlab.local') | Add-RemoteConnection  -Credential $Cred

## PARAMETERS

### -ComputerName
Specifies the system to add a \\\\ComputerName\IPC$ connection for.

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
Specifies the remote \\\\UNC\path to add the connection for.

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

### -Credential
A \[Management.Automation.PSCredential\] object of alternate credentials
for connection to the remote system.

```yaml
Type: PSCredential
Parameter Sets: (All)
Aliases: 

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS

