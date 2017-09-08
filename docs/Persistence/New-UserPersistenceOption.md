# New-UserPersistenceOption

## SYNOPSIS
Configure user-level persistence options for the Add-Persistence function.

PowerSploit Function: New-UserPersistenceOption  
Author: Matthew Graeber (@mattifestation)  
License: BSD 3-Clause  
Required Dependencies: None  
Optional Dependencies: None

## SYNTAX

### ScheduledTaskOnIdle
```
New-UserPersistenceOption [-ScheduledTask] [-OnIdle]
```

### ScheduledTaskHourly
```
New-UserPersistenceOption [-ScheduledTask] [-Hourly]
```

### ScheduledTaskDaily
```
New-UserPersistenceOption [-ScheduledTask] [-Daily] -At <DateTime>
```

### Registry
```
New-UserPersistenceOption [-Registry] [-AtLogon]
```

## DESCRIPTION
New-UserPersistenceOption allows for the configuration of elevated persistence options.
The output of this function is a required parameter of Add-Persistence.
Available persitence options in order of stealth are the following: scheduled task, registry.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
$UserOptions = New-UserPersistenceOption -Registry -AtLogon
```

### -------------------------- EXAMPLE 2 --------------------------
```
$UserOptions = New-UserPersistenceOption -ScheduledTask -OnIdle
```

## PARAMETERS

### -ScheduledTask
Persist via a scheduled task.

Detection Difficulty:        Moderate
Removal Difficulty:          Moderate
User Detectable? 
No

```yaml
Type: SwitchParameter
Parameter Sets: ScheduledTaskOnIdle, ScheduledTaskHourly, ScheduledTaskDaily
Aliases: 

Required: True
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -Registry
Persist via the HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run registry key.
Note: This option will briefly pop up a PowerShell console to the user.

Detection Difficulty:        Easy
Removal Difficulty:          Easy
User Detectable? 
Yes

```yaml
Type: SwitchParameter
Parameter Sets: Registry
Aliases: 

Required: True
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -Daily
Starts the payload daily.

```yaml
Type: SwitchParameter
Parameter Sets: ScheduledTaskDaily
Aliases: 

Required: True
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -Hourly
Starts the payload hourly.

```yaml
Type: SwitchParameter
Parameter Sets: ScheduledTaskHourly
Aliases: 

Required: True
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -At
Starts the payload at the specified time.
You may specify times in the following formats: '12:31 AM', '2 AM', '23:00:00', or '4:06:26 PM'.

```yaml
Type: DateTime
Parameter Sets: ScheduledTaskDaily
Aliases: 

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -OnIdle
Starts the payload after one minute of idling.

```yaml
Type: SwitchParameter
Parameter Sets: ScheduledTaskOnIdle
Aliases: 

Required: True
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -AtLogon
Starts the payload upon any user logon.

```yaml
Type: SwitchParameter
Parameter Sets: Registry
Aliases: 

Required: True
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS

[http://www.exploit-monday.com](http://www.exploit-monday.com)

