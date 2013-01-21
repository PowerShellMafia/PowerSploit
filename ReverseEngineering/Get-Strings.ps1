function Get-Strings
{
<#
.SYNOPSIS

Gets strings from a file.

PowerSploit Function: Get-Strings
Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

The Get-Strings cmdlet returns strings (Unicode and/or Ascii) from a file. This cmdlet is useful for dumping strings from binary file and was designed to replicate the functionality of strings.exe from Sysinternals.

.PARAMETER Path

Specifies the path to an item.

.PARAMETER Encoding

Specifies the file encoding. The default value returns both Unicode and Ascii.

.PARAMETER MinimumLength

Specifies the minimum length string to return. The default string length is 3.

.EXAMPLE

C:\PS> Get-Strings C:\Windows\System32\calc.exe

Description
-----------
Dump Unicode and Ascii strings of calc.exe.

.EXAMPLE

C:\PS> Get-ChildItem C:\Windows\System32\*.dll | Get-Strings -MinimumLength 12 -Encoding Ascii

Description
-----------
Dumps Ascii strings of at least length 12 of every dll located in C:\Windows\System32.

.NOTES

This cmdlet was designed to intentionally use only PowerShell cmdlets (no .NET methods) in order to be compatible with PowerShell on Windows RT (or any ConstrainedLanguage runspace).

.LINK

http://www.exploit-monday.com
#>

    Param
    (
        [Parameter(Position = 1, Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path $_ -PathType 'Leaf'})]
        [String[]]
        [Alias('PSPath')]
        $Path,

        [ValidateSet('Default','Ascii','Unicode')]
        [String]
        $Encoding = 'Default',

        [UInt32]
        $MinimumLength = 3
    )

    BEGIN
    {
        $FileContents = ''
    }
    PROCESS
    {
        foreach ($File in $Path)
        {
            if ($Encoding -eq 'Unicode' -or $Encoding -eq 'Default')
            {
                $UnicodeFileContents = Get-Content -Encoding 'Unicode' $File
                $UnicodeRegex = [Regex] "[\u0020-\u007E]{$MinimumLength,}"
                $Results += $UnicodeRegex.Matches($UnicodeFileContents)
            }
            
            if ($Encoding -eq 'Ascii' -or $Encoding -eq 'Default')
            {
                $AsciiFileContents = Get-Content -Encoding 'UTF7' $File
                $AsciiRegex = [Regex] "[\x20-\x7E]{$MinimumLength,}"
                $Results = $AsciiRegex.Matches($AsciiFileContents)
            }

            $Results | ForEach-Object { Write-Output $_.Value }
        }
    }
    END {}
}