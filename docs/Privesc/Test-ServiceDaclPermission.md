# Test-ServiceDaclPermission

## SYNOPSIS
Tests one or more passed services or service names against a given permission set,
returning the service objects where the current user have the specified permissions.

Author: Will Schroeder (@harmj0y), Matthew Graeber (@mattifestation)  
License: BSD 3-Clause  
Required Dependencies: Add-ServiceDacl

## SYNTAX

```
Test-ServiceDaclPermission [-Name] <String[]> [-Permissions <String[]>] [-PermissionSet <String>]
```

## DESCRIPTION
Takes a service Name or a ServiceProcess.ServiceController on the pipeline, and first adds
a service Dacl to the service object with Add-ServiceDacl.
All group SIDs for the current
user are enumerated services where the user has some type of permission are filtered.
The
services are then filtered against a specified set of permissions, and services where the
current user have the specified permissions are returned.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-Service | Test-ServiceDaclPermission
```

Return all service objects where the current user can modify the service configuration.

### -------------------------- EXAMPLE 2 --------------------------
```
Get-Service | Test-ServiceDaclPermission -PermissionSet 'Restart'
```

Return all service objects that the current user can restart.

### -------------------------- EXAMPLE 3 --------------------------
```
Test-ServiceDaclPermission -Permissions 'Start' -Name 'VulnSVC'
```

Return the VulnSVC object if the current user has start permissions.

## PARAMETERS

### -Name
An array of one or more service names to test against the specified permission set.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases: ServiceName, Service

Required: True
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -Permissions
A manual set of permission to test again.
One of:'QueryConfig', 'ChangeConfig', 'QueryStatus',
'EnumerateDependents', 'Start', 'Stop', 'PauseContinue', 'Interrogate', UserDefinedControl',
'Delete', 'ReadControl', 'WriteDac', 'WriteOwner', 'Synchronize', 'AccessSystemSecurity',
'GenericAll', 'GenericExecute', 'GenericWrite', 'GenericRead', 'AllAccess'

```yaml
Type: String[]
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -PermissionSet
A pre-defined permission set to test a specified service against.
'ChangeConfig', 'Restart', or 'AllAccess'.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: ChangeConfig
Accept pipeline input: False
Accept wildcard characters: False
```

## INPUTS

## OUTPUTS

### ServiceProcess.ServiceController

## NOTES

## RELATED LINKS

[https://rohnspowershellblog.wordpress.com/2013/03/19/viewing-service-acls/](https://rohnspowershellblog.wordpress.com/2013/03/19/viewing-service-acls/)

