# Get-ProcessTokenGroup

## SYNOPSIS
Returns all SIDs that the current token context is a part of, whether they are disabled or not.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect, Get-TokenInformation

## SYNTAX

```
Get-ProcessTokenGroup [[-Id] <UInt32>]
```

## DESCRIPTION
First, if a process ID is passed, then the process is opened using OpenProcess(),
otherwise GetCurrentProcess() is used to open up a pseudohandle to the current process.
OpenProcessToken() is then used to get a handle to the specified process token.
The token
is then passed to Get-TokenInformation to query the current token groups for the specified
token.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-ProcessTokenGroup
```

SID                                              Attributes                     ProcessId
---                                              ----------                     ---------
S-1-5-21-890171859-3433809...
..._DEFAULT, SE_GROUP_ENABLED                          1372
S-1-1-0                       ..._DEFAULT, SE_GROUP_ENABLED                          1372
S-1-5-32-544                     SE_GROUP_USE_FOR_DENY_ONLY                          1372
S-1-5-32-545                  ..._DEFAULT, SE_GROUP_ENABLED                          1372
S-1-5-4                       ..._DEFAULT, SE_GROUP_ENABLED                          1372
S-1-2-1                       ..._DEFAULT, SE_GROUP_ENABLED                          1372
S-1-5-11                      ..._DEFAULT, SE_GROUP_ENABLED                          1372
S-1-5-15                      ..._DEFAULT, SE_GROUP_ENABLED                          1372
S-1-5-5-0-419601              ...SE_GROUP_INTEGRITY_ENABLED                          1372
S-1-2-0                       ..._DEFAULT, SE_GROUP_ENABLED                          1372
S-1-5-21-890171859-3433809...
..._DEFAULT, SE_GROUP_ENABLED                          1372
S-1-5-21-890171859-3433809...
..._DEFAULT, SE_GROUP_ENABLED                          1372
S-1-5-21-890171859-3433809...
..._DEFAULT, SE_GROUP_ENABLED                          1372
S-1-18-1                      ..._DEFAULT, SE_GROUP_ENABLED                          1372
S-1-16-8192                                                                          1372

### -------------------------- EXAMPLE 2 --------------------------
```
Get-Process notepad | Get-ProcessTokenGroup
```

SID                                              Attributes                     ProcessId
---                                              ----------                     ---------
S-1-5-21-890171859-3433809...
..._DEFAULT, SE_GROUP_ENABLED                          2640
S-1-1-0                       ..._DEFAULT, SE_GROUP_ENABLED                          2640
S-1-5-32-544                     SE_GROUP_USE_FOR_DENY_ONLY                          2640
S-1-5-32-545                  ..._DEFAULT, SE_GROUP_ENABLED                          2640
S-1-5-4                       ..._DEFAULT, SE_GROUP_ENABLED                          2640
S-1-2-1                       ..._DEFAULT, SE_GROUP_ENABLED                          2640
S-1-5-11                      ..._DEFAULT, SE_GROUP_ENABLED                          2640
S-1-5-15                      ..._DEFAULT, SE_GROUP_ENABLED                          2640
S-1-5-5-0-419601              ...SE_GROUP_INTEGRITY_ENABLED                          2640
S-1-2-0                       ..._DEFAULT, SE_GROUP_ENABLED                          2640
S-1-5-21-890171859-3433809...
..._DEFAULT, SE_GROUP_ENABLED                          2640
S-1-5-21-890171859-3433809...
..._DEFAULT, SE_GROUP_ENABLED                          2640
S-1-5-21-890171859-3433809...
..._DEFAULT, SE_GROUP_ENABLED                          2640
S-1-18-1                      ..._DEFAULT, SE_GROUP_ENABLED                          2640
S-1-16-8192                                                                          2640

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

