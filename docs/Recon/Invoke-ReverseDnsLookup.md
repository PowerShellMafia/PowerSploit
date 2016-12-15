# Invoke-ReverseDnsLookup

## SYNOPSIS
Perform a reverse DNS lookup scan on a range of IP addresses.

PowerSploit Function: Invoke-ReverseDnsLookup  
Author: Matthew Graeber (@mattifestation)  
License: BSD 3-Clause  
Required Dependencies: None  
Optional Dependencies: None

## SYNTAX

```
Invoke-ReverseDnsLookup [-IpRange] <String>
```

## DESCRIPTION
Invoke-ReverseDnsLookup scans an IP address range for DNS PTR records.
This script is useful for performing DNS reconnaissance prior to conducting an authorized penetration test.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Invoke-ReverseDnsLookup 74.125.228.0/29
```

IP              HostName
--              --------
74.125.228.1    iad23s05-in-f1.1e100.net
74.125.228.2    iad23s05-in-f2.1e100.net
74.125.228.3    iad23s05-in-f3.1e100.net
74.125.228.4    iad23s05-in-f4.1e100.net
74.125.228.5    iad23s05-in-f5.1e100.net
74.125.228.6    iad23s05-in-f6.1e100.net

Description
-----------
Returns the hostnames of the IP addresses specified by the CIDR range.

### -------------------------- EXAMPLE 2 --------------------------
```
Invoke-ReverseDnsLookup '74.125.228.1,74.125.228.4-74.125.228.6'
```

IP              HostName
--              --------
74.125.228.1    iad23s05-in-f1.1e100.net
74.125.228.4    iad23s05-in-f4.1e100.net
74.125.228.5    iad23s05-in-f5.1e100.net
74.125.228.6    iad23s05-in-f6.1e100.net

Description
-----------
Returns the hostnames of the IP addresses specified by the IP range specified.

### -------------------------- EXAMPLE 3 --------------------------
```
Write-Output "74.125.228.1,74.125.228.0/29" | Invoke-ReverseDnsLookup
```

IP                                                          HostName
--                                                          --------
74.125.228.1                                                iad23s05-in-f1.1e100.net
74.125.228.1                                                iad23s05-in-f1.1e100.net
74.125.228.2                                                iad23s05-in-f2.1e100.net
74.125.228.3                                                iad23s05-in-f3.1e100.net
74.125.228.4                                                iad23s05-in-f4.1e100.net
74.125.228.5                                                iad23s05-in-f5.1e100.net
74.125.228.6                                                iad23s05-in-f6.1e100.net

Description
-----------
Returns the hostnames of the IP addresses piped from another source.

## PARAMETERS

### -IpRange
Specifies the IP address range.
The range provided can be in the form of a single IP address, a low-high range, or a CIDR range.
Comma-delimited ranges may can be provided.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: True
Position: 1
Default value: None
Accept pipeline input: True (ByValue)
Accept wildcard characters: False
```

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS

[http://www.exploit-monday.com
https://github.com/mattifestation/PowerSploit]()

