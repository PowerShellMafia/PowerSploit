# Get-WebConfig

## SYNOPSIS
This script will recover cleartext and encrypted connection strings from all web.config
files on the system.
Also, it will decrypt them if needed.

Author: Scott Sutherland, Antti Rantasaari  
License: BSD 3-Clause  
Required Dependencies: None

## SYNTAX

```
Get-WebConfig
```

## DESCRIPTION
This script will identify all of the web.config files on the system and recover the
connection strings used to support authentication to backend databases. 
If needed, the
script will also decrypt the connection strings on the fly. 
The output supports the
pipeline which can be used to convert all of the results into a pretty table by piping
to format-table.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Return a list of cleartext and decrypted connect strings from web.config files.
```

Get-WebConfig

user   : s1admin
pass   : s1password
dbserv : 192.168.1.103\server1
vdir   : C:\test2
path   : C:\test2\web.config
encr   : No

user   : s1user
pass   : s1password
dbserv : 192.168.1.103\server1
vdir   : C:\inetpub\wwwroot
path   : C:\inetpub\wwwroot\web.config
encr   : Yes

### -------------------------- EXAMPLE 2 --------------------------
```
Return a list of clear text and decrypted connect strings from web.config files.
```

Get-WebConfig | Format-Table -Autosize

user    pass       dbserv                vdir               path                          encr
----    ----       ------                ----               ----                          ----
s1admin s1password 192.168.1.101\server1 C:\App1            C:\App1\web.config            No
s1user  s1password 192.168.1.101\server1 C:\inetpub\wwwroot C:\inetpub\wwwroot\web.config No
s2user  s2password 192.168.1.102\server2 C:\App2            C:\App2\test\web.config       No
s2user  s2password 192.168.1.102\server2 C:\App2            C:\App2\web.config            Yes
s3user  s3password 192.168.1.103\server3 D:\App3            D:\App3\web.config            No

## PARAMETERS

## INPUTS

## OUTPUTS

### System.Boolean

System.Data.DataTable

## NOTES
Below is an alterantive method for grabbing connection strings, but it doesn't support decryption.
for /f "tokens=*" %i in ('%systemroot%\system32\inetsrv\appcmd.exe list sites /text:name') do %systemroot%\system32\inetsrv\appcmd.exe list config "%i" -section:connectionstrings

Author: Scott Sutherland - 2014, NetSPI
Author: Antti Rantasaari - 2014, NetSPI

## RELATED LINKS

[https://github.com/darkoperator/Posh-SecMod/blob/master/PostExploitation/PostExploitation.psm1
http://www.netspi.com
https://raw2.github.com/NetSPI/cmdsql/master/cmdsql.aspx
http://www.iis.net/learn/get-started/getting-started-with-iis/getting-started-with-appcmdexe
http://msdn.microsoft.com/en-us/library/k6h9cz8h(v=vs.80).aspx](https://github.com/darkoperator/Posh-SecMod/blob/master/PostExploitation/PostExploitation.psm1
http://www.netspi.com
https://raw2.github.com/NetSPI/cmdsql/master/cmdsql.aspx
http://www.iis.net/learn/get-started/getting-started-with-iis/getting-started-with-appcmdexe
http://msdn.microsoft.com/en-us/library/k6h9cz8h(v=vs.80).aspx)

