# Invoke-Portscan

## SYNOPSIS
Simple portscan module

PowerSploit Function: Invoke-Portscan  
Author: Rich Lundeen (http://webstersProdigy.net)  
License: BSD 3-Clause  
Required Dependencies: None  
Optional Dependencies: None

## SYNTAX

### cmdHosts
```
Invoke-Portscan -Hosts <String[]> [-ExcludeHosts <String>] [-Ports <String>] [-PortFile <String>]
 [-TopPorts <String>] [-ExcludedPorts <String>] [-SkipDiscovery] [-PingOnly] [-DiscoveryPorts <String>]
 [-Threads <Int32>] [-nHosts <Int32>] [-Timeout <Int32>] [-SleepTimer <Int32>] [-SyncFreq <Int32>] [-T <Int32>]
 [-GrepOut <String>] [-XmlOut <String>] [-ReadableOut <String>] [-AllformatsOut <String>] [-noProgressMeter]
 [-quiet] [-ForceOverwrite]
```

### fHosts
```
Invoke-Portscan -HostFile <String> [-ExcludeHosts <String>] [-Ports <String>] [-PortFile <String>]
 [-TopPorts <String>] [-ExcludedPorts <String>] [-SkipDiscovery] [-PingOnly] [-DiscoveryPorts <String>]
 [-Threads <Int32>] [-nHosts <Int32>] [-Timeout <Int32>] [-SleepTimer <Int32>] [-SyncFreq <Int32>] [-T <Int32>]
 [-GrepOut <String>] [-XmlOut <String>] [-ReadableOut <String>] [-AllformatsOut <String>] [-noProgressMeter]
 [-quiet] [-ForceOverwrite]
```

## DESCRIPTION
Does a simple port scan using regular sockets, based (pretty) loosely on nmap

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Invoke-Portscan -Hosts "webstersprodigy.net,google.com,microsoft.com" -TopPorts 50
```

Description
-----------
Scans the top 50 ports for hosts found for webstersprodigy.net,google.com, and microsoft.com

### -------------------------- EXAMPLE 2 --------------------------
```
echo webstersprodigy.net | Invoke-Portscan -oG test.gnmap -f -ports "80,443,8080"
```

Description
-----------
Does a portscan of "webstersprodigy.net", and writes a greppable output file

### -------------------------- EXAMPLE 3 --------------------------
```
Invoke-Portscan -Hosts 192.168.1.1/24 -T 4 -TopPorts 25 -oA localnet
```

Description
-----------
Scans the top 20 ports for hosts found in the 192.168.1.1/24 range, outputs all file formats

## PARAMETERS

### -Hosts
Include these comma seperated hosts (supports IPv4 CIDR notation) or pipe them in

```yaml
Type: String[]
Parameter Sets: cmdHosts
Aliases: 

Required: True
Position: Named
Default value: None
Accept pipeline input: True (ByValue)
Accept wildcard characters: False
```

### -HostFile
Input hosts from file rather than commandline

```yaml
Type: String
Parameter Sets: fHosts
Aliases: iL

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExcludeHosts
Exclude these comma seperated hosts

```yaml
Type: String
Parameter Sets: (All)
Aliases: exclude

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Ports
Include these comma seperated ports (can also be a range like 80-90)

```yaml
Type: String
Parameter Sets: (All)
Aliases: p

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -PortFile
Input ports from a file

```yaml
Type: String
Parameter Sets: (All)
Aliases: iP

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -TopPorts
Include the x top ports - only goes to 1000, default is top 50

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExcludedPorts
Exclude these comma seperated ports

```yaml
Type: String
Parameter Sets: (All)
Aliases: xPorts

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SkipDiscovery
Treat all hosts as online, skip host discovery

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: Pn

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -PingOnly
Ping scan only (disable port scan)

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: sn

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -DiscoveryPorts
Comma separated ports used for host discovery.
-1 is a ping

```yaml
Type: String
Parameter Sets: (All)
Aliases: PS

Required: False
Position: Named
Default value: -1,445,80,443
Accept pipeline input: False
Accept wildcard characters: False
```

### -Threads
number of max threads for the thread pool (per host)

```yaml
Type: Int32
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: 100
Accept pipeline input: False
Accept wildcard characters: False
```

### -nHosts
number of hosts to concurrently scan

```yaml
Type: Int32
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: 25
Accept pipeline input: False
Accept wildcard characters: False
```

### -Timeout
Timeout time on a connection in miliseconds before port is declared filtered

```yaml
Type: Int32
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: 2000
Accept pipeline input: False
Accept wildcard characters: False
```

### -SleepTimer
Wait before thread checking, in miliseconds

```yaml
Type: Int32
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: 500
Accept pipeline input: False
Accept wildcard characters: False
```

### -SyncFreq
How often (in terms of hosts) to sync threads and flush output

```yaml
Type: Int32
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: 1024
Accept pipeline input: False
Accept wildcard characters: False
```

### -T
\[0-5\] shortcut performance options.
Default is 3.
higher is more aggressive.
Sets (nhosts, threads,timeout)
    5 {$nHosts=30;  $Threads = 1000; $Timeout = 750  }
    4 {$nHosts=25;  $Threads = 1000; $Timeout = 1200 }
    3 {$nHosts=20;  $Threads = 100;  $Timeout = 2500 }
    2 {$nHosts=15;  $Threads = 32;   $Timeout = 3000 }
    1 {$nHosts=10;  $Threads = 32;   $Timeout = 5000 }

```yaml
Type: Int32
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: 0
Accept pipeline input: False
Accept wildcard characters: False
```

### -GrepOut
Greppable output file

```yaml
Type: String
Parameter Sets: (All)
Aliases: oG

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -XmlOut
output XML file

```yaml
Type: String
Parameter Sets: (All)
Aliases: oX

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ReadableOut
output file in 'readable' format

```yaml
Type: String
Parameter Sets: (All)
Aliases: oN

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -AllformatsOut
output in readable (.nmap), xml (.xml), and greppable (.gnmap) formats

```yaml
Type: String
Parameter Sets: (All)
Aliases: oA

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -noProgressMeter
Suppresses the progress meter

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -quiet
supresses returned output and don't store hosts in memory - useful for very large scans

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: q

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -ForceOverwrite
Force Overwrite if output Files exist.
Otherwise it throws exception

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: F

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS

[http://webstersprodigy.net](http://webstersprodigy.net)

