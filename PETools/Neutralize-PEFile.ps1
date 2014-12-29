function Neutralize-PEFile
{
<#
.SYNOPSIS

Parses a PE file header, decrements the entry point address by 1, and replaces the entry point code with a breakpoint (0xcc). 
This effectively neutralizes the EXE. The data at EntryPoint-1 is usually padding, so all code is preserved and the PE can still be debugged.

Optionally, an offset in to the file can be specified indicating the offset where a PE file was embedded in the file specified.
You can find this offset using a tool such as HexEdit and looking for the MZ header. 
This is useful when debugging an exploit which drops an embedded malicious EXE to disk and executes it.

PowerSploit Function: Get-PEHeader
Author: Joe 'clymb3r' Bialek (@JosephBialek)
License: BSD 3-Clause
Required Dependencies: Get-PEHeader.ps1
Optional Dependencies: None

.DESCRIPTION

Neutralize-PEFile decrements the PE entry point by 0x1 and sets it to be a breakpoint so the PE can be debugged and distributed safely.
Optionally, an offset in to the file can be specified indicating where a PE file begins if it was embedded in another file.

.PARAMETER Path

Specifies the path to the portable executable file on disk (or a file with an embedded PE file)

.PARAMETER Bytes

Specifies a byte array that contains a PE file.

.PARAMETER PEOffset

The byte offset in the file/bytearray where a PE file starts.

.EXAMPLE

C:\PS> Neutralize-PEFile -Path c:\POCs\virus.exe

Description
-----------
Overwrites the first instruction in virus.exe with a breakpoint.

.EXAMPLE

C:\PS> Neutralize-PEFile -Path c:\POCs\evil.bin -PEOffset 100

Description
-----------
Opens evil.bin, starts parsing a PE file at offset 100 and overwrites the first instruction in the embedded PE file with a breakpoint.

.EXAMPLE

C:\PS> Neutralize-PEFile -Bytes $PEBytes

Description
-----------
Parses the PE file contained in the byte array and overwrites the first instruction with a breakpoint.

.NOTES

The magic values / signatures will be checked when parsing the PE file. This should act as a safety check in case you accidentally try to parse 
a invalid PE file.

.LINK

https://github.com/clymb3r
https://github.com/mattifestation/PowerSploit

#>
    Param(
        [Parameter(Position = 0, Mandatory = $True, ParameterSetName = 'PEPath')]
        [String]
        $Path,

        [Parameter(Position = 0, Mandatory = $True, ParameterSetName = 'PEBytes')]
        [Byte[]]
        $Bytes,

        [Parameter(Position = 1, Mandatory = $False)]
        [UInt32]
        $Offset = 0
    )


    function Get-Hex
    {
        Param(
            [Int]$Value
        )

        $Hex = "0x{0:x}" -f $Value
        return $Hex
    }

    [System.IO.Directory]::SetCurrentDirectory($pwd)

    if ($PsCmdlet.ParameterSetName -eq 'PEPath')
    {
        $FileBytes = Get-Content -Path $Path -Encoding Byte
    }
    else
    {
        $FileBytes = $Bytes
    }

    $PEBytes = $FileBytes[$Offset..($FileBytes.Length - 1)]
    $PEHeader = Get-PEHeader -PEBytes $PEBytes -Validate

    if ($PEHeader -eq $null)
    {
        Write-Error "Error calling Get-PEHeader."
    }

    # RVA to the PE entry point from the PE HANDLE
    $AddressOfEntryPointRva = $PEHeader.OptionalHeader.AddressOfEntryPoint

    Write-Verbose "Original AddressOfEntryPoint (RVA to Entry from PE HANDLE): $(Get-Hex $AddressOfEntryPointRva)"
    $AddressOfEntryPointIndex = $Offset + $PEHeader.OptionalHeader.AddressOfEntryPoint + 40 <#Index in to OptionalHeader#>
    $NewAddressOfEntryPoint = [Byte[]][BitConverter]::GetBytes([UInt32]($Header.OptionalHeader.AddressOfEntryPoint - 1))
    for($i = 0; $i -lt 4; $i++)
    {
        $PEBytes[$AddressOfEntryPointIndex + $i] = $NewAddressOfEntryPoint[$i]
    }
    $AddressOfEntryPointRva = [BitConverter]::ToUInt32($PEBytes[$AddressOfEntryPointIndex..($AddressOfEntryPointIndex+3)], 0)
    Write-Verbose "Modified AddressOfEntryPoint: $(Get-Hex $AddressOfEntryPointRva)"


    # Get the address where the function will be written
    # Loop through all the sections and find the section that the AddressOfEntryPoint points to
    $EntryFound = $False
    foreach ($Section in $PEHeader.SectionHeaders)
    {
        $VirtualSize = $Section.VirtualSize                # Size of the section when loaded in memory
        $VirtualAddress = $Section.VirtualAddress          # RVA the section will be loaded to in memory (offset from PE HANDLE)
        $PointerToRawData = $Section.PointerToRawData      # RVA the section is located at from the start of the PE on disk

        Write-Debug "Section Range: $(Get-Hex $VirtualAddress) - $(Get-Hex($VirtualAddress + $VirtualSize))"

        if (($AddressOfEntryPointRva -ge $Section.VirtualAddress) -and ($AddressOfEntryPointRva -le ($Section.VirtualAddress + $Section.VirtualSize)))
        {
            $EntryPointIndex = $AddressOfEntryPointRva - $VirtualAddress + $PointerToRawData
            Write-Verbose "Instruction at modified AddressOfEntryPoint: $(Get-Hex $PEBytes[$EntryPointIndex])"

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
        $FileBytes[$Offset + $i] = $PEBytes[$i]
    }

    if ($PsCmdlet.ParameterSetName -eq 'PEPath')
    {
        Write-Verbose "Writing neutralized PE file to: $Path"
        [System.IO.File]::WriteAllBytes("$Path", $FileBytes)
    }
    else
    {
        return $FileBytes
    }
}