function Out-CompressedDll
{
<#
.SYNOPSIS

Compresses, Base-64 encodes, and outputs generated code to load a managed dll in memory.

PowerSploit Function: Out-CompressedDll
Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Out-CompressedDll outputs code that loads a compressed representation of a managed dll in memory as a byte array.

.PARAMETER FilePath

Specifies the path to a managed executable.

.EXAMPLE

C:\PS> Out-CompressedDll -FilePath evil.dll

Description
-----------
Compresses, base64 encodes, and outputs the code required to load evil.dll in memory.

.NOTES

Only pure MSIL-based dlls can be loaded using this technique. Native or IJW ('it just works' - mixed-mode) dlls will not load.

.LINK

http://www.exploit-monday.com/2012/12/in-memory-dll-loading.html
#>

    [CmdletBinding()] Param (
        [Parameter(Mandatory = $True)]
        [String]
        $FilePath
    )

    $Path = Resolve-Path $FilePath

    if (! [IO.File]::Exists($Path))
    {
        Throw "$Path does not exist."
    }

    $FileBytes = [System.IO.File]::ReadAllBytes($Path)

    if (($FileBytes[0..1] | % {[Char]$_}) -join '' -cne 'MZ')
    {
        Throw "$Path is not a valid executable."
    }

    $Length = $FileBytes.Length
    $CompressedStream = New-Object IO.MemoryStream
    $DeflateStream = New-Object IO.Compression.DeflateStream ($CompressedStream, [IO.Compression.CompressionMode]::Compress)
    $DeflateStream.Write($FileBytes, 0, $FileBytes.Length)
    $DeflateStream.Dispose()
    $CompressedFileBytes = $CompressedStream.ToArray()
    $CompressedStream.Dispose()
    $EncodedCompressedFile = [Convert]::ToBase64String($CompressedFileBytes)

    Write-Verbose "Compression ratio: $(($EncodedCompressedFile.Length/$FileBytes.Length).ToString('#%'))"

    $Output = @"
`$EncodedCompressedFile = @'
$EncodedCompressedFile
'@
`$DeflatedStream = New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String(`$EncodedCompressedFile),[IO.Compression.CompressionMode]::Decompress)
`$UncompressedFileBytes = New-Object Byte[]($Length)
`$DeflatedStream.Read(`$UncompressedFileBytes, 0, $Length) | Out-Null
[Reflection.Assembly]::Load(`$UncompressedFileBytes)
"@

    Write-Output $Output
}
