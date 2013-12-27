#requires -Version 3

function Get-CSDisassembly
{
<#
.SYNOPSIS

    Disassembles a byte array using the Capstone Engine disassembly framework.

    PowerSploit Function: Get-CSDisassembly
    Author: Matthew Graeber (@mattifestation)
    License: See LICENSE.TXT
    Required Dependencies: lib\capstone.dll, lib\[x86|x64]\libcapstone.dll
    Optional Dependencies: None

.DESCRIPTION

    Get-CSDisassembly is compatible on 32 and 64-bit.

.PARAMETER Architecture

    Specifies the architecture of the code to be disassembled.

.PARAMETER Mode

    Specifies the mode in which to disassemble code. For example, to disassemble Amd64 code, architecture is set to 'X86' and Mode is set to 'MODE_64'.

.PARAMETER Code

    A byte array consisting of the code to be disassembled.

.PARAMETER Offset

    Specifies the starting address of the disassembly listing.

.PARAMETER Count

    Specifies the maximum number of instructions to disassemble.

.PARAMETER Syntax

    Specifies the syntax flavor to be used (INTEL vs. ATT).

.PARAMETER DetailOff

    Specifies that detailed parsing should not be performed - i.e. do not perform additional analysis beyond disassembling.
      
.EXAMPLE

    C:\PS>$Bytes = [Byte[]] @( 0x8D, 0x4C, 0x32, 0x08, 0x01, 0xD8, 0x81, 0xC6, 0x34, 0x12, 0x00, 0x00 )
    Get-CSDisassembly -Architecture X86 -Mode Mode16 -Code $Bytes -Offset 0x1000

.EXAMPLE

    C:\PS>$Bytes = [Byte[]] @( 0x8D, 0x4C, 0x32, 0x08, 0x01, 0xD8, 0x81, 0xC6, 0x34, 0x12, 0x00, 0x00 )
    Get-CSDisassembly -Architecture X86 -Mode Mode32 -Code $Bytes -Syntax ATT

.INPUTS

    None

    You cannot pipe objects to Get-CSDisassembly.

.OUTPUTS

    Capstone.Instruction[]

    Get-CSDisassembly returns an array of Instruction objects.
#>

    [OutputType([Capstone.Instruction])]
    [CmdletBinding()] Param (
        [Parameter(Mandatory)]
        [Capstone.Architecture]
        $Architecture,

        [Parameter(Mandatory)]
        [Capstone.Mode]
        $Mode,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Byte[]]
        $Code,

        [UInt64]
        $Offset = 0,

        [UInt32]
        $Count = 0,

        [ValidateSet('Intel', 'ATT')]
        [String]
        $Syntax,

        [Switch]
        $DetailOff
    )

    $Disassembly = New-Object Capstone.Capstone($Architecture, $Mode)

    if ($Syntax)
    {
        switch ($Syntax)
        {
            'Intel' { $SyntaxMode = [Capstone.OptionValue]::SyntaxIntel }
            'ATT'   { $SyntaxMode = [Capstone.OptionValue]::SyntaxATT }
        }

        $Disassembly.SetSyntax($SyntaxMode)
    }

    if ($DetailOff)
    {
        $Disassembly.SetDetail($False)
    }

    $Disassembly.Disassemble($Code, $Offset, $Count)
}