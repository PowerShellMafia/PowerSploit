# Get-WMIRegProxy

## SYNOPSIS
Enumerates the proxy server and WPAD conents for the current user.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None

## SYNTAX

```
Get-WMIRegProxy [[-ComputerName] <String[]>] [-Credential <PSCredential>]
```

## DESCRIPTION
Enumerates the proxy server and WPAD specification for the current user
on the local machine (default), or a machine specified with -ComputerName.
It does this by enumerating settings from
HKU:SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-WMIRegProxy
```

ComputerName           ProxyServer            AutoConfigURL         Wpad
------------           -----------            -------------         ----
WINDOWS1               http://primary.test...

### -------------------------- EXAMPLE 2 --------------------------
```
$Cred = Get-Credential "TESTLAB\administrator"
```

Get-WMIRegProxy -Credential $Cred -ComputerName primary.testlab.local

ComputerName            ProxyServer            AutoConfigURL         Wpad
------------            -----------            -------------         ----
windows1.testlab.local  primary.testlab.local

## PARAMETERS

### -ComputerName
Specifies the system to enumerate proxy settings on.
Defaults to the local host.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases: HostName, dnshostname, name

Required: False
Position: 1
Default value: $Env:COMPUTERNAME
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -Credential
A \[Management.Automation.PSCredential\] object of alternate credentials
for connecting to the remote system.

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

Accepts one or more computer name specification strings  on the pipeline (netbios or FQDN).

## OUTPUTS

### PowerView.ProxySettings

Outputs custom PSObjects with the ComputerName, ProxyServer, AutoConfigURL, and WPAD contents.

## NOTES

## RELATED LINKS

