# Get-NetComputerSiteName

## SYNOPSIS
Returns the AD site where the local (or a remote) machine resides.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect, Invoke-UserImpersonation, Invoke-RevertToSelf

## SYNTAX

```
Get-NetComputerSiteName [[-ComputerName] <String[]>] [-Credential <PSCredential>]
```

## DESCRIPTION
This function will use the DsGetSiteName Win32API call to look up the
name of the site where a specified computer resides.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-NetComputerSiteName -ComputerName WINDOWS1.testlab.local
```

Returns the site for WINDOWS1.testlab.local.

### -------------------------- EXAMPLE 2 --------------------------
```
Get-DomainComputer | Get-NetComputerSiteName
```

Returns the sites for every machine in AD.

### -------------------------- EXAMPLE 3 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-NetComputerSiteName -ComputerName WINDOWS1.testlab.local -Credential $Cred

## PARAMETERS

### -ComputerName
Specifies the hostname to check the site for (also accepts IP addresses).
Defaults to 'localhost'.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases: HostName, dnshostname, name

Required: False
Position: 1
Default value: Localhost
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -Credential
A \[Management.Automation.PSCredential\] object of alternate credentials
for connection to the remote system using Invoke-UserImpersonation.

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

### PowerView.ComputerSite

A PSCustomObject containing the ComputerName, IPAddress, and associated Site name.

## NOTES

## RELATED LINKS

