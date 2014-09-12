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

.PARAMETER DetailOn

    Specifies that detailed parsing should be performed - i.e. provide detailed information for each disassembled instruction.

.PARAMETER Verstion

    Prints the running Capstone Framework version.
      
.EXAMPLE

    $Bytes = [Byte[]] @( 0x8D, 0x4C, 0x32, 0x08, 0x01, 0xD8, 0x81, 0xC6, 0x34, 0x12, 0x00, 0x00 )
    Get-CSDisassembly -Architecture X86 -Mode Mode16 -Code $Bytes -Offset 0x1000

    $Bytes = [Byte[]] @( 0x8D, 0x4C, 0x32, 0x08, 0x01, 0xD8, 0x81, 0xC6, 0x34, 0x12, 0x00, 0x00 )
    Get-CSDisassembly -Architecture X86 -Mode Mode32 -Code $Bytes

    $Bytes = [Byte[]] @( 0x8D, 0x4C, 0x32, 0x08, 0x01, 0xD8, 0x81, 0xC6, 0x34, 0x12, 0x00, 0x00 )
    Get-CSDisassembly -Architecture X86 -Mode Mode32 -Code $Bytes -Syntax ATT

    $Bytes = [Byte[]] @( 0x55, 0x48, 0x8b, 0x05, 0xb8, 0x13, 0x00, 0x00 )
    Get-CSDisassembly -Architecture X86 -Mode Mode64 -Code $Bytes -DetailOn

    $Bytes = [Byte[]] @( 0xED, 0xFF, 0xFF, 0xEB, 0x04, 0xe0, 0x2d, 0xe5, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x83, 0x22, 0xe5, 0xf1, 0x02, 0x03, 0x0e, 0x00, 0x00, 0xa0, 0xe3, 0x02, 0x30, 0xc1, 0xe7, 0x00, 0x00, 0x53, 0xe3 )
    Get-CSDisassembly -Architecture Arm -Mode Arm -Code $Bytes

    $Bytes = [Byte[]] @( 0x4f, 0xf0, 0x00, 0x01, 0xbd, 0xe8, 0x00, 0x88, 0xd1, 0xe8, 0x00, 0xf0 )
    Get-CSDisassembly -Architecture Arm -Mode Thumb -Code $Bytes

    $Bytes = [Byte[]] @( 0x10, 0xf1, 0x10, 0xe7, 0x11, 0xf2, 0x31, 0xe7, 0xdc, 0xa1, 0x2e, 0xf3, 0xe8, 0x4e, 0x62, 0xf3 )
    Get-CSDisassembly -Architecture Arm -Mode Arm -Code $Bytes

    $Bytes = [Byte[]] @( 0x70, 0x47, 0xeb, 0x46, 0x83, 0xb0, 0xc9, 0x68 )
    Get-CSDisassembly -Architecture Arm -Mode Thumb -Code $Bytes -DetailOn

    $Bytes = [Byte[]] @( 0x21, 0x7c, 0x02, 0x9b, 0x21, 0x7c, 0x00, 0x53, 0x00, 0x40, 0x21, 0x4b, 0xe1, 0x0b, 0x40, 0xb9 )
    Get-CSDisassembly -Architecture Arm64 -Mode Arm -Code $Bytes

    $Bytes = [Byte[]] @( 0x0C, 0x10, 0x00, 0x97, 0x00, 0x00, 0x00, 0x00, 0x24, 0x02, 0x00, 0x0c, 0x8f, 0xa2, 0x00, 0x00, 0x34, 0x21, 0x34, 0x56 )
    Get-CSDisassembly -Architecture Mips -Mode 'Mode32, BigEndian' -Code $Bytes

    $Bytes = [Byte[]] @( 0x56, 0x34, 0x21, 0x34, 0xc2, 0x17, 0x01, 0x00 )
    Get-CSDisassembly -Architecture Mips -Mode 'Mode64, LittleEndian' -Code $Bytes

    $Bytes = [Byte[]] @( 0x80, 0x20, 0x00, 0x00, 0x80, 0x3f, 0x00, 0x00, 0x10, 0x43, 0x23, 0x0e, 0xd0, 0x44, 0x00, 0x80, 0x4c, 0x43, 0x22, 0x02, 0x2d, 0x03, 0x00, 0x80, 0x7c, 0x43, 0x20, 0x14, 0x7c, 0x43, 0x20, 0x93, 0x4f, 0x20, 0x00, 0x21, 0x4c, 0xc8, 0x00, 0x21 )
    Get-CSDisassembly -Architecture PPC -Mode BigEndian -Code $Bytes

.INPUTS

    None

    You cannot pipe objects to Get-CSDisassembly.

.OUTPUTS

    Capstone.Instruction[]

    Get-CSDisassembly returns an array of Instruction objects.
#>

    [OutputType([Capstone.Instruction])]
    [CmdletBinding(DefaultParameterSetName = 'Disassemble')]
    Param (
        [Parameter(Mandatory, ParameterSetName = 'Disassemble')]
        [Capstone.Architecture]
        $Architecture,

        [Parameter(Mandatory, ParameterSetName = 'Disassemble')]
        [Capstone.Mode]
        $Mode,

        [Parameter(Mandatory, ParameterSetName = 'Disassemble')]
        [ValidateNotNullOrEmpty()]
        [Byte[]]
        $Code,

        [Parameter( ParameterSetName = 'Disassemble' )]
        [UInt64]
        $Offset = 0,

        [Parameter( ParameterSetName = 'Disassemble' )]
        [UInt32]
        $Count = 0,

        [Parameter( ParameterSetName = 'Disassemble' )]
        [ValidateSet('Intel', 'ATT')]
        [String]
        $Syntax,

        [Parameter( ParameterSetName = 'Disassemble' )]
        [Switch]
        $DetailOn,

        [Parameter( ParameterSetName = 'Version' )]
        [Switch]
        $Version
    )

    if ($PsCmdlet.ParameterSetName -eq 'Version')
    {
        $Disassembly = New-Object Capstone.Capstone([Capstone.Architecture]::X86, [Capstone.Mode]::Mode16)
        $Disassembly.Version

        return
    }

    $Disassembly = New-Object Capstone.Capstone($Architecture, $Mode)

    if ($Disassembly.Version -ne [Capstone.Capstone]::BindingVersion)
    {
        Write-Error "capstone.dll version ($([Capstone.Capstone]::BindingVersion.ToString())) should be the same as libcapstone.dll version. Otherwise, undefined behavior is likely."
    }

    if ($Syntax)
    {
        switch ($Syntax)
        {
            'Intel' { $SyntaxMode = [Capstone.OptionValue]::SyntaxIntel }
            'ATT'   { $SyntaxMode = [Capstone.OptionValue]::SyntaxATT }
        }

        $Disassembly.SetSyntax($SyntaxMode)
    }

    if ($DetailOn)
    {
        $Disassembly.SetDetail($True)
    }

    $Disassembly.Disassemble($Code, $Offset, $Count)
}