# Get-DomainUserEvent

## SYNOPSIS
Enumerate account logon events (ID 4624) and Logon with explicit credential
events (ID 4648) from the specified host (default of the localhost).

Author: Lee Christensen (@tifkin_), Justin Warner (@sixdub), Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None

## SYNTAX

```
Get-DomainUserEvent [[-ComputerName] <String[]>] [-StartTime <DateTime>] [-EndTime <DateTime>]
 [-MaxEvents <Int32>] [-Credential <PSCredential>]
```

## DESCRIPTION
This function uses an XML path filter passed to Get-WinEvent to retrieve
security events with IDs of 4624 (logon events) or 4648 (explicit credential
logon events) from -StartTime (default of now-1 day) to -EndTime (default of now).
A maximum of -MaxEvents (default of 5000) are returned.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-DomainUserEvent
```

Return logon events on the local machine.

### -------------------------- EXAMPLE 2 --------------------------
```
Get-DomainController | Get-DomainUserEvent -StartTime ([DateTime]::Now.AddDays(-3))
```

Return all logon events from the last 3 days from every domain controller in the current domain.

### -------------------------- EXAMPLE 3 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainUserEvent -ComputerName PRIMARY.testlab.local -Credential $Cred -MaxEvents 1000

Return a max of 1000 logon events from the specified machine using the specified alternate credentials.

## PARAMETERS

### -ComputerName
Specifies the computer name to retrieve events from, default of localhost.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases: dnshostname, HostName, name

Required: False
Position: 1
Default value: $Env:COMPUTERNAME
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -StartTime
The \[DateTime\] object representing the start of when to collect events.
Default of \[DateTime\]::Now.AddDays(-1).

```yaml
Type: DateTime
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: [DateTime]::Now.AddDays(-1)
Accept pipeline input: False
Accept wildcard characters: False
```

### -EndTime
The \[DateTime\] object representing the end of when to collect events.
Default of \[DateTime\]::Now.

```yaml
Type: DateTime
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: [DateTime]::Now
Accept pipeline input: False
Accept wildcard characters: False
```

### -MaxEvents
The maximum number of events to retrieve.
Default of 5000.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: 5000
Accept pipeline input: False
Accept wildcard characters: False
```

### -Credential
A \[Management.Automation.PSCredential\] object of alternate credentials
for connection to the target computer.

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

### PowerView.LogonEvent

PowerView.ExplicitCredentialLogonEvent

## NOTES

## RELATED LINKS

[http://www.sixdub.net/2014/11/07/offensive-event-parsing-bringing-home-trophies/](http://www.sixdub.net/2014/11/07/offensive-event-parsing-bringing-home-trophies/)

