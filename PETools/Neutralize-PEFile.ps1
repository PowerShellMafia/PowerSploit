function Neutralize-PEFile
{
<#
.SYNOPSIS

Parses a PE file header and replaces the entry point code with a breakpoint (0xcc). This effectively neutralizes the EXE.
Optionally, an offset in to the file can be specified indicating the offset where a PE file was embedded in the file specified. You can find this offset using a tool
such as HexEdit and looking for the MZ header. This is useful when debugging an exploit which drops an embedded malicious EXE to disk and executes it.

PowerSploit Function: Get-PEHeader
Author: Joe 'clymb3r' Bialek (@JosephBialek)
License: BSD 3-Clause
Required Dependencies: Get-PEHeader.ps1
Optional Dependencies: None

.DESCRIPTION

Neutralize-PEFile replaces the first instruction of a PE file with a breakpoint. Optionally, an offset in to the file can be specified indicating where a PE file begins if it was embedded in another file.

.PARAMETER Path

Specifies the path to the portable executable file on disk (or a file with an embedded PE file)

.PARAMETER PEOffset

The byte offset in the file where a PE file starts.

.EXAMPLE

C:\PS> Neutralize-PEFile -Path c:\POCs\virus.exe

Description
-----------
Overwrites the first instruction in virus.exe with a breakpoint.

.EXAMPLE

C:\PS> Neutralize-PEFile -Path c:\POCs\evil.bin -Offset 100

Description
-----------
Opens evil.bin, starts parsing a PE file at offset 100 and overwrites the first instruction in the embedded PE file with a breakpoint.

.NOTES

If the PE file is malformed, this tool could crash. This tool does not attempt to verify the PE file is structured correctly.

.LINK

https://github.com/clymb3r
https://github.com/mattifestation/PowerSploit

#>
    Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $Path,

        [Parameter(Position = 0, Mandatory = $False)]
        [UInt32]
        $PEOffset = 0
    )


    function Get-Hex
    {
        Param(
            [Int]$Value
        )

        $Hex = "0x{0:x}" -f $Value
        return $Hex
    }


    $FileBytes = Get-Content -Path $Path -Encoding Byte
    $PEBytes = $FileBytes[$PEOffset..($FileBytes.Length - 1)]
    $PEHeader = Get-PEHeader -PEBytes $PEBytes

    # RVA to the PE entry point from the PE HANDLE
    $EntryAddr = $PEHeader.OptionalHeader.AddressOfEntryPoint

    Write-Debug "AddressOfEntryPoint (RVA to Entry from PE HANDLE): $(Get-Hex $EntryAddr)"

    # Get the address where the function will be written
    # Loop through all the sections and find the section that the AddressOfEntryPoint points to
    $EntryFound = $False
    foreach ($Section in $PEHeader.SectionHeaders)
    {
        $VirtualSize = $Section.VirtualSize                # Size of the section when loaded in memory
        $VirtualAddress = $Section.VirtualAddress          # RVA the section will be loaded to in memory (offset from PE HANDLE)
        $PointerToRawData = $Section.PointerToRawData      # RVA the section is located at from the start of the PE on disk

        Write-Debug "Section Range: $(Get-Hex $VirtualAddress) - $(Get-Hex($VirtualAddress + $VirtualSize))"

        if (($EntryAddr -ge $Section.VirtualAddress) -and ($EntryAddr -le ($Section.VirtualAddress + $Section.VirtualSize)))
        {
            $EntryPointIndex = $EntryAddr - $VirtualAddress + $PointerToRawData
            Write-Output "Section containing entry point found. Instruction byte: $(Get-Hex $PEBytes[$EntryPointIndex])"

            $PEBytes[$EntryPointIndex] = 0xcc
            $EntryFound = $True

            break
        }
    }

    if (-not $EntryFound)
    {
        Write-Error "Couldn't locate the section that the AddressOfEntryPoint is located in" -ErrorAction Stop
    }

    # Write the changes back in to the FileBytes array
    for($i = 0; $i -lt $PEBytes.Length; $i++)
    {
        $FileBytes[$PEOffset + $i] = $PEBytes[$i]
    }

    Write-Output "Writing neutralized PE file to: $PWD\$Path"
    [System.IO.File]::WriteAllBytes("$PWD\$Path", $FileBytes)
}