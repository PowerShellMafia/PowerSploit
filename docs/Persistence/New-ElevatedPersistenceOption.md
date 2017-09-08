# New-ElevatedPersistenceOption

## SYNOPSIS
Configure elevated persistence options for the Add-Persistence function.

PowerSploit Function: New-ElevatedPersistenceOption  
Author: Matthew Graeber (@mattifestation)  
License: BSD 3-Clause  
Required Dependencies: None  
Optional Dependencies: None

## SYNTAX

### PermanentWMIAtStartup
```
New-ElevatedPersistenceOption [-PermanentWMI] [-AtStartup]
```

### PermanentWMIDaily
```
New-ElevatedPersistenceOption [-PermanentWMI] [-Daily] -At <DateTime>
```

### ScheduledTaskOnIdle
```
New-ElevatedPersistenceOption [-ScheduledTask] [-OnIdle]
```

### ScheduledTaskAtLogon
```
New-ElevatedPersistenceOption [-ScheduledTask] [-AtLogon]
```

### ScheduledTaskHourly
```
New-ElevatedPersistenceOption [-ScheduledTask] [-Hourly]
```

### ScheduledTaskDaily
```
New-ElevatedPersistenceOption [-ScheduledTask] [-Daily] -At <DateTime>
```

### Registry
```
New-ElevatedPersistenceOption [-Registry] [-AtLogon]
```

## DESCRIPTION
New-ElevatedPersistenceOption allows for the configuration of elevated persistence options.
The output of this function is a required parameter of Add-Persistence.
Available persitence options in order of stealth are the following: permanent WMI subscription, scheduled task, and registry.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
$ElevatedOptions = New-ElevatedPersistenceOption -PermanentWMI -Daily -At '3 PM'
```

### -------------------------- EXAMPLE 2 --------------------------
```
$ElevatedOptions = New-ElevatedPersistenceOption -Registry -AtStartup
```

### -------------------------- EXAMPLE 3 --------------------------
```
$ElevatedOptions = New-ElevatedPersistenceOption -ScheduledTask -OnIdle
```

## PARAMETERS

### -PermanentWMI
Persist via a permanent WMI event subscription.
This option will be the most difficult to detect and remove.

Detection Difficulty:        Difficult
Removal Difficulty:          Difficult
User Detectable? 
No

```yaml
Type: SwitchParameter
Parameter Sets: PermanentWMIAtStartup, PermanentWMIDaily
Aliases: 

Required: True
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -ScheduledTask
Persist via a scheduled task.

Detection Difficulty:        Moderate
Removal Difficulty:          Moderate
User Detectable? 
No

```yaml
Type: SwitchParameter
Parameter Sets: ScheduledTaskOnIdle, ScheduledTaskAtLogon, ScheduledTaskHourly, ScheduledTaskDaily
Aliases: 

Required: True
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -Registry
Persist via the HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run registry key.
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
Parameter Sets: PermanentWMIDaily, ScheduledTaskDaily
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
Parameter Sets: PermanentWMIDaily, ScheduledTaskDaily
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
Parameter Sets: ScheduledTaskAtLogon, Registry
Aliases: 

Required: True
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -AtStartup
Starts the payload within 240 and 325 seconds of computer startup.

```yaml
Type: SwitchParameter
Parameter Sets: PermanentWMIAtStartup
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

