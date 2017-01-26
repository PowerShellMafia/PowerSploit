# Get-ProcessTokenPrivilege

## SYNOPSIS
Returns all privileges for the current (or specified) process ID.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect, Get-TokenInformation

## SYNTAX

```
Get-ProcessTokenPrivilege [[-Id] <UInt32>] [-Special]
```

## DESCRIPTION
First, if a process ID is passed, then the process is opened using OpenProcess(),
otherwise GetCurrentProcess() is used to open up a pseudohandle to the current process.
OpenProcessToken() is then used to get a handle to the specified process token.
The token
is then passed to Get-TokenInformation to query the current privileges for the specified
token.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-ProcessTokenPrivilege
```

Privilege                    Attributes                     ProcessId
                    ---------                    ----------                     ---------
          SeShutdownPrivilege                      DISABLED                          2600
      SeChangeNotifyPrivilege ...AULT, SE_PRIVILEGE_ENABLED                          2600
            SeUndockPrivilege                      DISABLED                          2600
SeIncreaseWorkingSetPrivilege                      DISABLED                          2600
          SeTimeZonePrivilege                      DISABLED                          2600

### -------------------------- EXAMPLE 2 --------------------------
```
Get-ProcessTokenPrivilege -Special
```

Privilege                                  Attributes                 ProcessId
---------                                  ----------                 ---------
SeSecurityPrivilege                          DISABLED                      2444
SeTakeOwnershipPrivilege                     DISABLED                      2444
SeBackupPrivilege                            DISABLED                      2444
SeRestorePrivilege                           DISABLED                      2444
SeSystemEnvironmentPriv... 
DISABLED                      2444
SeImpersonatePrivilege     ...T, SE_PRIVILEGE_ENABLED                      2444

### -------------------------- EXAMPLE 3 --------------------------
```
Get-Process notepad | Get-ProcessTokenPrivilege | fl
```

Privilege  : SeShutdownPrivilege
Attributes : DISABLED
ProcessId  : 2640

Privilege  : SeChangeNotifyPrivilege
Attributes : SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
ProcessId  : 2640

Privilege  : SeUndockPrivilege
Attributes : DISABLED
ProcessId  : 2640

Privilege  : SeIncreaseWorkingSetPrivilege
Attributes : DISABLED
ProcessId  : 2640

Privilege  : SeTimeZonePrivilege
Attributes : DISABLED
ProcessId  : 2640

## PARAMETERS

### -Id
The process ID to enumerate token groups for, otherwise defaults to the current process.

```yaml
Type: UInt32
Parameter Sets: (All)
Aliases: ProcessID

Required: False
Position: 1
Default value: 0
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -Special
Switch.
Only return 'special' privileges, meaning admin-level privileges.
These include SeSecurityPrivilege, SeTakeOwnershipPrivilege, SeLoadDriverPrivilege, SeBackupPrivilege,
SeRestorePrivilege, SeDebugPrivilege, SeSystemEnvironmentPrivilege, SeImpersonatePrivilege, SeTcbPrivilege.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: Privileged

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

## INPUTS

## OUTPUTS

### PowerUp.TokenGroup

Outputs a custom object containing the token group (SID/attributes) for the specified token if
"-InformationClass 'Groups'" is passed.

PowerUp.TokenPrivilege

Outputs a custom object containing the token privilege (name/attributes) for the specified token if
"-InformationClass 'Privileges'" is passed

## NOTES

## RELATED LINKS

