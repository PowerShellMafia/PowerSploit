# Restore-ServiceBinary

## SYNOPSIS
Restores a service binary backed up by Install-ServiceBinary.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-ServiceDetail, Get-ModifiablePath

## SYNTAX

```
Restore-ServiceBinary [-Name] <String> [[-BackupPath] <String>]
```

## DESCRIPTION
Takes a service Name or a ServiceProcess.ServiceController on the pipeline and
checks for the existence of an "OriginalServiceBinary.exe.bak" in the service
binary location.
If it exists, the backup binary is restored to the original
binary path.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Restore-ServiceBinary -Name VulnSVC
```

Restore the original binary for the service 'VulnSVC'.

### -------------------------- EXAMPLE 2 --------------------------
```
Get-Service VulnSVC | Restore-ServiceBinary
```

Restore the original binary for the service 'VulnSVC'.

### -------------------------- EXAMPLE 3 --------------------------
```
Restore-ServiceBinary -Name VulnSVC -BackupPath 'C:\temp\backup.exe'
```

Restore the original binary for the service 'VulnSVC' from a custom location.

## PARAMETERS

### -Name
The service name to restore a binary for.

```yaml
Type: String
Parameter Sets: (All)
Aliases: ServiceName

Required: True
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -BackupPath
Optional manual path to the backup binary.

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

## INPUTS

## OUTPUTS

### PowerUp.ServiceBinary.Installed

## NOTES

## RELATED LINKS

