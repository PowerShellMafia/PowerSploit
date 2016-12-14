# Get-SiteListPassword

## SYNOPSIS
Retrieves the plaintext passwords for found McAfee's SiteList.xml files.
Based on Jerome Nokin (@funoverip)'s Python solution (in links).

Author: Jerome Nokin (@funoverip)  
PowerShell Port: @harmj0y  
License: BSD 3-Clause  
Required Dependencies: None

## SYNTAX

```
Get-SiteListPassword [[-Path] <String[]>]
```

## DESCRIPTION
Searches for any McAfee SiteList.xml in C:\Program Files\, C:\Program Files (x86)\,
C:\Documents and Settings\, or C:\Users\.
For any files found, the appropriate
credential fields are extracted and decrypted using the internal Get-DecryptedSitelistPassword
function that takes advantage of McAfee's static key encryption.
Any decrypted credentials
are output in custom objects.
See links for more information.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-SiteListPassword
```

EncPassword : jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q==
UserName    :
Path        : Products/CommonUpdater
Name        : McAfeeHttp
DecPassword : MyStrongPassword!
Enabled     : 1
DomainName  :
Server      : update.nai.com:80

EncPassword : jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q==
UserName    : McAfeeService
Path        : Repository$
Name        : Paris
DecPassword : MyStrongPassword!
Enabled     : 1
DomainName  : companydomain
Server      : paris001

EncPassword : jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q==
UserName    : McAfeeService
Path        : Repository$
Name        : Tokyo
DecPassword : MyStrongPassword!
Enabled     : 1
DomainName  : companydomain
Server      : tokyo000

## PARAMETERS

### -Path
Optional path to a SiteList.xml file or folder.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases: 

Required: False
Position: 1
Default value: None
Accept pipeline input: True (ByValue)
Accept wildcard characters: False
```

## INPUTS

## OUTPUTS

### PowerUp.SiteListPassword

## NOTES

## RELATED LINKS

[https://github.com/funoverip/mcafee-sitelist-pwd-decryption/
https://funoverip.net/2016/02/mcafee-sitelist-xml-password-decryption/
https://github.com/tfairane/HackStory/blob/master/McAfeePrivesc.md
https://www.syss.de/fileadmin/dokumente/Publikationen/2011/SySS_2011_Deeg_Privilege_Escalation_via_Antivirus_Software.pdf](https://github.com/funoverip/mcafee-sitelist-pwd-decryption/
https://funoverip.net/2016/02/mcafee-sitelist-xml-password-decryption/
https://github.com/tfairane/HackStory/blob/master/McAfeePrivesc.md
https://www.syss.de/fileadmin/dokumente/Publikationen/2011/SySS_2011_Deeg_Privilege_Escalation_via_Antivirus_Software.pdf)

