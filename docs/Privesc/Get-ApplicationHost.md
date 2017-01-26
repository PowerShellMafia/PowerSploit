# Get-ApplicationHost

## SYNOPSIS
Recovers encrypted application pool and virtual directory passwords from the applicationHost.config on the system.

Author: Scott Sutherland  
License: BSD 3-Clause  
Required Dependencies: None

## SYNTAX

```
Get-ApplicationHost
```

## DESCRIPTION
This script will decrypt and recover application pool and virtual directory passwords
from the applicationHost.config file on the system. 
The output supports the
pipeline which can be used to convert all of the results into a pretty table by piping
to format-table.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Return application pool and virtual directory passwords from the applicationHost.config on the system.
```

Get-ApplicationHost

user    : PoolUser1
pass    : PoolParty1!
type    : Application Pool
vdir    : NA
apppool : ApplicationPool1
user    : PoolUser2
pass    : PoolParty2!
type    : Application Pool
vdir    : NA
apppool : ApplicationPool2
user    : VdirUser1
pass    : VdirPassword1!
type    : Virtual Directory
vdir    : site1/vdir1/
apppool : NA
user    : VdirUser2
pass    : VdirPassword2!
type    : Virtual Directory
vdir    : site2/
apppool : NA

### -------------------------- EXAMPLE 2 --------------------------
```
Return a list of cleartext and decrypted connect strings from web.config files.
```

Get-ApplicationHost | Format-Table -Autosize

user          pass               type              vdir         apppool
----          ----               ----              ----         -------
PoolUser1     PoolParty1! 
Application Pool   NA           ApplicationPool1
PoolUser2     PoolParty2! 
Application Pool   NA           ApplicationPool2
VdirUser1     VdirPassword1! 
Virtual Directory  site1/vdir1/ NA
VdirUser2     VdirPassword2! 
Virtual Directory  site2/       NA

## PARAMETERS

## INPUTS

## OUTPUTS

### System.Data.DataTable

System.Boolean

## NOTES
Author: Scott Sutherland - 2014, NetSPI
Version: Get-ApplicationHost v1.0
Comments: Should work on IIS 6 and Above

## RELATED LINKS

[https://github.com/darkoperator/Posh-SecMod/blob/master/PostExploitation/PostExploitation.psm1
http://www.netspi.com
http://www.iis.net/learn/get-started/getting-started-with-iis/getting-started-with-appcmdexe
http://msdn.microsoft.com/en-us/library/k6h9cz8h(v=vs.80).aspx](https://github.com/darkoperator/Posh-SecMod/blob/master/PostExploitation/PostExploitation.psm1
http://www.netspi.com
http://www.iis.net/learn/get-started/getting-started-with-iis/getting-started-with-appcmdexe
http://msdn.microsoft.com/en-us/library/k6h9cz8h(v=vs.80).aspx)

