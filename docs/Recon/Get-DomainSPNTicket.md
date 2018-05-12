# Get-DomainSPNTicket

## SYNOPSIS
Request the kerberos ticket for a specified service principal name (SPN).

Author: machosec, Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Invoke-UserImpersonation, Invoke-RevertToSelf

## SYNTAX

### RawSPN (Default)
```
Get-DomainSPNTicket [-SPN] <String[]> [-OutputFormat <String>] [-Credential <PSCredential>]
```

### User
```
Get-DomainSPNTicket [-User] <Object[]> [-OutputFormat <String>] [-Credential <PSCredential>]
```

## DESCRIPTION
This function will either take one/more SPN strings, or one/more PowerView.User objects
(the output from Get-DomainUser) and will request a kerberos ticket for the given SPN
using System.IdentityModel.Tokens.KerberosRequestorSecurityToken.
The encrypted
portion of the ticket is then extracted and output in either crackable John or Hashcat
format (deafult of John).

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-DomainSPNTicket -SPN "HTTP/web.testlab.local"
```

Request a kerberos service ticket for the specified SPN.

### -------------------------- EXAMPLE 2 --------------------------
```
"HTTP/web1.testlab.local","HTTP/web2.testlab.local" | Get-DomainSPNTicket
```

Request kerberos service tickets for all SPNs passed on the pipeline.

### -------------------------- EXAMPLE 3 --------------------------
```
Get-DomainUser -SPN | Get-DomainSPNTicket -OutputFormat Hashcat
```

Request kerberos service tickets for all users with non-null SPNs and output in Hashcat format.

## PARAMETERS

### -SPN
Specifies the service principal name to request the ticket for.

```yaml
Type: String[]
Parameter Sets: RawSPN
Aliases: ServicePrincipalName

Required: True
Position: 1
Default value: None
Accept pipeline input: True (ByValue)
Accept wildcard characters: False
```

### -User
Specifies a PowerView.User object (result of Get-DomainUser) to request the ticket for.

```yaml
Type: Object[]
Parameter Sets: User
Aliases: 

Required: True
Position: 1
Default value: None
Accept pipeline input: True (ByValue)
Accept wildcard characters: False
```

### -OutputFormat
Either 'John' for John the Ripper style hash formatting, or 'Hashcat' for Hashcat format.
Defaults to 'John'.

```yaml
Type: String
Parameter Sets: (All)
Aliases: Format

Required: False
Position: Named
Default value: John
Accept pipeline input: False
Accept wildcard characters: False
```

### -Credential
A \[Management.Automation.PSCredential\] object of alternate credentials
for connection to the remote domain using Invoke-UserImpersonation.

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

### String

Accepts one or more SPN strings on the pipeline with the RawSPN parameter set.

### PowerView.User

Accepts one or more PowerView.User objects on the pipeline with the User parameter set.

## OUTPUTS

### PowerView.SPNTicket

Outputs a custom object containing the SamAccountName, ServicePrincipalName, and encrypted ticket section.

## NOTES

## RELATED LINKS

