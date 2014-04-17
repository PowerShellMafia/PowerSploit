filter ConvertTo-String
{
<#
.SYNOPSIS

Converts the bytes of a file to a string.

PowerSploit Function: ConvertTo-String
Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

ConvertTo-String converts the bytes of a file to a string that has a
1-to-1 mapping back to the file's original bytes. ConvertTo-String is
useful for performing binary regular expressions.

.PARAMETER Path

Specifies the path to the file to convert.

.EXAMPLE

PS C:\>$BinaryString = ConvertTo-String C:\Windows\SysWow64\kernel32.dll
PS C:\>$HotpatchableRegex = [Regex] '[\xCC\x90]{5}\x8B\xFF'
PS C:\>$HotpatchableRegex.Matches($BinaryString)

Description
-----------
Converts kernel32.dll into a string. A binary regular expression is
then performed on the string searching for a hotpatchable code
sequence - i.e. 5 nop/int3 followed by a mov edi, edi instruction.

.NOTES

The intent of ConvertTo-String is not to replicate the functionality
of strings.exe, rather it is intended to be used when
performing regular expressions on binary data.

.LINK

http://www.exploit-monday.com
#>

    [OutputType([String])]
    Param (
        [Parameter( Mandatory = $True,
                    Position = 0,
                    ValueFromPipeline = $True )]
        [ValidateScript({-not (Test-Path $_ -PathType Container)})]
        [String]
        $Path
    )

    $FileStream = New-Object -TypeName IO.FileStream -ArgumentList (Resolve-Path $Path), 'Open', 'Read'

    # Note: Codepage 28591 returns a 1-to-1 char to byte mapping
    $Encoding = [Text.Encoding]::GetEncoding(28591)
    
    $StreamReader = New-Object IO.StreamReader($FileStream, $Encoding)

    $BinaryText = $StreamReader.ReadToEnd()

    $StreamReader.Close()
    $FileStream.Close()

    Write-Output $BinaryText
}
