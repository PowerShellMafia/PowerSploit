# Get-CachedGPPPassword

## SYNOPSIS
Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences and
left in cached files on the host.

Author: Chris Campbell (@obscuresec)  
License: BSD 3-Clause  
Required Dependencies: None

## SYNTAX

```
Get-CachedGPPPassword
```

## DESCRIPTION
Get-CachedGPPPassword searches the local machine for cached for groups.xml, scheduledtasks.xml, services.xml and
datasources.xml files and returns plaintext passwords.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-CachedGPPPassword
```

NewName   : \[BLANK\]
Changed   : {2013-04-25 18:36:07}
Passwords : {Super!!!Password}
UserNames : {SuperSecretBackdoor}
File      : C:\ProgramData\Microsoft\Group Policy\History\{32C4C89F-7
            C3A-4227-A61D-8EF72B5B9E42}\Machine\Preferences\Groups\Gr
            oups.xml

## PARAMETERS

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS

[http://www.obscuresecurity.blogspot.com/2012/05/gpp-password-retrieval-with-powershell.html
https://github.com/mattifestation/PowerSploit/blob/master/Recon/Get-GPPPassword.ps1
https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/gpp.rb
http://esec-pentest.sogeti.com/exploiting-windows-2008-group-policy-preferences
http://rewtdance.blogspot.com/2012/06/exploiting-windows-2008-group-policy.html](http://www.obscuresecurity.blogspot.com/2012/05/gpp-password-retrieval-with-powershell.html
https://github.com/mattifestation/PowerSploit/blob/master/Recon/Get-GPPPassword.ps1
https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/gpp.rb
http://esec-pentest.sogeti.com/exploiting-windows-2008-group-policy-preferences
http://rewtdance.blogspot.com/2012/06/exploiting-windows-2008-group-policy.html)

