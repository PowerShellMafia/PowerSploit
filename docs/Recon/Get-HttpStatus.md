# Get-HttpStatus

## SYNOPSIS
Returns the HTTP Status Codes and full URL for specified paths.

PowerSploit Function: Get-HttpStatus  
Author: Chris Campbell (@obscuresec)  
License: BSD 3-Clause  
Required Dependencies: None  
Optional Dependencies: None

## SYNTAX

```
Get-HttpStatus [-Target] <String> [[-Path] <String>] [[-Port] <Int32>] [-UseSSL]
```

## DESCRIPTION
A script to check for the existence of a path or file on a webserver.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-HttpStatus -Target www.example.com -Path c:\dictionary.txt | Select-Object {where StatusCode -eq 20*}
```

### -------------------------- EXAMPLE 2 --------------------------
```
Get-HttpStatus -Target www.example.com -Path c:\dictionary.txt -UseSSL
```

## PARAMETERS

### -Target
Specifies the remote web host either by IP or hostname.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Path
Specifies the remost host.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: 2
Default value: .\Dictionaries\admin.txt
Accept pipeline input: False
Accept wildcard characters: False
```

### -Port
Specifies the port to connect to.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases: 

Required: False
Position: 3
Default value: 0
Accept pipeline input: False
Accept wildcard characters: False
```

### -UseSSL
Use an SSL connection.

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

## INPUTS

## OUTPUTS

## NOTES
HTTP Status Codes: 100 - Informational * 200 - Success * 300 - Redirection * 400 - Client Error * 500 - Server Error

## RELATED LINKS

[http://obscuresecurity.blogspot.com
http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html]()

