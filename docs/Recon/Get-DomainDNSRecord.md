# Get-DomainDNSRecord

## SYNOPSIS
Enumerates the Active Directory DNS records for a given zone.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Convert-LDAPProperty, Convert-DNSRecord

## SYNTAX

```
Get-DomainDNSRecord [-ZoneName] <String> [-Domain <String>] [-Server <String>] [-Properties <String[]>]
 [-ResultPageSize <Int32>] [-ServerTimeLimit <Int32>] [-FindOne] [-Credential <PSCredential>]
```

## DESCRIPTION
Given a specific Active Directory DNS zone name, query for all 'dnsNode'
LDAP entries using that zone as the search base.
Return all DNS entry results
and use Convert-DNSRecord to try to convert the binary DNS record blobs.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-DomainDNSRecord -ZoneName testlab.local
```

Retrieve all records for the testlab.local zone.

### -------------------------- EXAMPLE 2 --------------------------
```
Get-DomainDNSZone | Get-DomainDNSRecord
```

Retrieve all records for all zones in the current domain.

### -------------------------- EXAMPLE 3 --------------------------
```
Get-DomainDNSZone -Domain dev.testlab.local | Get-DomainDNSRecord -Domain dev.testlab.local
```

Retrieve all records for all zones in the dev.testlab.local domain.

## PARAMETERS

### -ZoneName
Specifies the zone to query for records (which can be enumearted with Get-DomainDNSZone).

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: True
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -Domain
The domain to query for zones, defaults to the current domain.

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

### -Server
Specifies an Active Directory server (domain controller) to bind to for the search.

```yaml
Type: String
Parameter Sets: (All)
Aliases: DomainController

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Properties
Specifies the properties of the output object to retrieve from the server.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: Name,distinguishedname,dnsrecord,whencreated,whenchanged
Accept pipeline input: False
Accept wildcard characters: False
```

### -ResultPageSize
Specifies the PageSize to set for the LDAP searcher object.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: 200
Accept pipeline input: False
Accept wildcard characters: False
```

### -ServerTimeLimit
Specifies the maximum amount of time the server spends searching.
Default of 120 seconds.

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

### -FindOne
Only return one result object.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: ReturnOne

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -Credential
A \[Management.Automation.PSCredential\] object of alternate credentials
for connection to the target domain.

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

### PowerView.DNSRecord

Outputs custom PSObjects with detailed information about the DNS record entry.

## NOTES

## RELATED LINKS

