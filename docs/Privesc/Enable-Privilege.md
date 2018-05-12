# Enable-Privilege

## SYNOPSIS
Enables a specific privilege for the current process.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect

## SYNTAX

```
Enable-Privilege [-Privilege] <String[]>
```

## DESCRIPTION
Uses RtlAdjustPrivilege to enable a specific privilege for the current process.
Privileges can be passed by string, or the output from Get-ProcessTokenPrivilege
can be passed on the pipeline.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-ProcessTokenPrivilege
```

Privilege                    Attributes                     ProcessId
                    ---------                    ----------                     ---------
          SeShutdownPrivilege                      DISABLED                          3620
      SeChangeNotifyPrivilege ...AULT, SE_PRIVILEGE_ENABLED                          3620
            SeUndockPrivilege                      DISABLED                          3620
SeIncreaseWorkingSetPrivilege                      DISABLED                          3620
          SeTimeZonePrivilege                      DISABLED                          3620

Enable-Privilege SeShutdownPrivilege

Get-ProcessTokenPrivilege

                    Privilege                    Attributes                     ProcessId
                    ---------                    ----------                     ---------
          SeShutdownPrivilege          SE_PRIVILEGE_ENABLED                          3620
      SeChangeNotifyPrivilege ...AULT, SE_PRIVILEGE_ENABLED                          3620
            SeUndockPrivilege                      DISABLED                          3620
SeIncreaseWorkingSetPrivilege                      DISABLED                          3620
          SeTimeZonePrivilege                      DISABLED                          3620

### -------------------------- EXAMPLE 2 --------------------------
```
Get-ProcessTokenPrivilege
```

Privilege                                        Attributes                     ProcessId
---------                                        ----------                     ---------
SeShutdownPrivilege                                DISABLED                          2828
SeChangeNotifyPrivilege       ...AULT, SE_PRIVILEGE_ENABLED                          2828
SeUndockPrivilege                                  DISABLED                          2828
SeIncreaseWorkingSetPrivilege                      DISABLED                          2828
SeTimeZonePrivilege                                DISABLED                          2828


Get-ProcessTokenPrivilege | Enable-Privilege -Verbose
VERBOSE: Attempting to enable SeShutdownPrivilege
VERBOSE: Attempting to enable SeChangeNotifyPrivilege
VERBOSE: Attempting to enable SeUndockPrivilege
VERBOSE: Attempting to enable SeIncreaseWorkingSetPrivilege
VERBOSE: Attempting to enable SeTimeZonePrivilege

Get-ProcessTokenPrivilege

Privilege                                        Attributes                     ProcessId
---------                                        ----------                     ---------
SeShutdownPrivilege                    SE_PRIVILEGE_ENABLED                          2828
SeChangeNotifyPrivilege       ...AULT, SE_PRIVILEGE_ENABLED                          2828
SeUndockPrivilege                      SE_PRIVILEGE_ENABLED                          2828
SeIncreaseWorkingSetPrivilege          SE_PRIVILEGE_ENABLED                          2828
SeTimeZonePrivilege                    SE_PRIVILEGE_ENABLED                          2828

## PARAMETERS

### -Privilege
{{Fill Privilege Description}}

```yaml
Type: String[]
Parameter Sets: (All)
Aliases: Privileges

Required: True
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS

[http://forum.sysinternals.com/tip-easy-way-to-enable-privileges_topic15745.html](http://forum.sysinternals.com/tip-easy-way-to-enable-privileges_topic15745.html)

