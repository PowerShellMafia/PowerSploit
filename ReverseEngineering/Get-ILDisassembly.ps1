function Get-ILDisassembly
{
<#
.SYNOPSIS

A MSIL (Microsoft Intermediate Language) disassembler.

PowerSploit Function: Get-ILDisassembly
Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Get-ILDisassembly disassembles a raw MSIL byte array passed in from a MethodInfo object in a manner similar to that of Ildasm.

The majority of this code was simply translated from C# (with permission) from a code example taken from: "C# 4.0 in a Nutshell", Copyright 2010, Joseph Albahari and Ben Albahari, pg. 728-733

.PARAMETER MethodInfo

A MethodInfo object that describes the implementation of the method and contains the IL for the method.

.EXAMPLE

C:\PS> [Int].GetMethod('Parse', [String]) | Get-ILDisassembly | Format-Table Position, Instruction, Operand -AutoSize

Position Instruction Operand
-------- ----------- -------
IL_0000  ldarg.0
IL_0001  ldc.i4.7
IL_0002  call        System.Globalization.NumberFormatInfo.get_CurrentInfo
IL_0007  call        System.Number.ParseInt32
IL_000C  ret

Description
-----------
Disassembles the System.Int32.Parse(String) method

.EXAMPLE

C:\PS> $MethodInfo = [Array].GetMethod('BinarySearch', [Type[]]([Array], [Object]))
C:\PS> Get-ILDisassembly $MethodInfo | Format-Table Position, Instruction, Operand -AutoSize

Position Instruction Operand
-------- ----------- -------
IL_0000  ldarg.0
IL_0001  brtrue.s    IL_000E
IL_0003  ldstr       'array'
IL_0008  newobj      System.ArgumentNullException..ctor
IL_000D  throw
IL_000E  ldarg.0
IL_000F  ldc.i4.0
IL_0010  callvirt    System.Array.GetLowerBound
IL_0015  stloc.0
IL_0016  ldarg.0
IL_0017  ldloc.0
IL_0018  ldarg.0
IL_0019  callvirt    System.Array.get_Length
IL_001E  ldarg.1
IL_001F  ldnull
IL_0020  call        System.Array.BinarySearch
IL_0025  ret

Description
-----------
Disassembles the System.Array.BinarySearch(Array, Object) method

.INPUTS

System.Reflection.MethodInfo

The method description containing the raw IL bytecodes.

.OUTPUTS

System.Object

Returns a custom object consisting of a position, instruction, and opcode parameter.
 
.LINK

http://www.exploit-monday.com
http://www.albahari.com/nutshell/cs4ch18.aspx
http://msdn.microsoft.com/en-us/library/system.reflection.emit.opcodes.aspx
http://www.ecma-international.org/publications/files/ECMA-ST/Ecma-335.pdf
#>

    Param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [System.Reflection.MethodInfo]
        $MethodInfo
    )

    if (!($MethodInfo.GetMethodBody())) {
        return
    }
    
    $IL = $MethodInfo.GetMethodBody().GetILAsByteArray()
    $MethodModule = $MethodInfo.DeclaringType.Module

    $OpCodeTable = @{}

    # Fill OpCodeTable with every OpCode so that it can be referenced by numeric byte value
    [System.Reflection.Emit.OpCodes].GetMembers() |
        ForEach-Object {
            try {
                $OpCode = $_.GetValue($null)
                $OpCodeTable[[Int16] $OpCode.Value] = $OpCode
            } catch {}
        }

    $Position = 0

    # Disassemble every instruction until the end of the IL bytecode array is reached
    while ($Position -lt $IL.Length) {

        # Get current instruction position
        $InstructionPostion = "IL_{0}" -f ($Position.ToString('X4'))

        if ($IL[$Position] -eq 0xFE) {
            # You are dealing with a two-byte opcode in this case
            $Op = $OpCodeTable[[Int16] ([BitConverter]::ToInt16($IL[($Position+1)..$Position], 0))]
            $Position++
        } else {
            # Otherwise, it's a one-byte opcode
            $Op = $OpCodeTable[[Int16] $IL[$Position]]
        }
        
        $Position++
        
        $Type = $Op.OperandType
        $Operand = $null
        
        if ($Type -eq 'InlineNone') {
            $OperandLength = 0
        } elseif (($Type -eq 'ShortInlineBrTarget') -or ($Type -eq 'ShortInlineI') -or ($Type -eq 'ShortInlineVar')) {
            $OperandLength = 1
            
            if ($Type -eq 'ShortInlineBrTarget') { # Short relative jump instruction
                # [SByte]::Parse was used because PowerShell doesn't handle signed bytes well
                $Target = $Position + ([SByte]::Parse($IL[$Position].ToString('X2'), 'AllowHexSpecifier')) + 1
                $Operand = "IL_{0}" -f ($Target.ToString('X4'))
            }
        } elseif ($Type -eq 'InlineVar') {
            $OperandLength = 2
        } elseif (($Type -eq 'InlineI8') -or (($Type -eq 'InlineR'))) {
            $OperandLength = 8
        } elseif ($Type -eq 'InlineSwitch') {
            # This is the only operand type with a variable number of operands
            $TargetCount = [BitConverter]::ToInt32($IL, $Position)
            $OperandLength = 4 * ($TargetCount + 1)
            $Targets = New-Object String[]($TargetCount)
            
            foreach ($i in 0..($TargetCount - 1)) {
                # Get all switch jump targets
                $Target = [BitConverter]::ToInt32($IL, ($Position + ($i + 1) * 4))
                $Targets[$i] = "IL_{0}" -f (($Position + $Target + $OperandLength).ToString('X4'))
            }
            
            $Operand = "({0})" -f ($Targets -join ',')
        } else {
            $OperandLength = 4
            $Operand = $null
            
            $OpInt = [BitConverter]::ToInt32($IL, $Position)
            
            if (($Type -eq 'InlineTok') -or ($Type -eq 'InlineMethod') -or ($Type -eq 'InlineField') -or ($Type -eq 'InlineType')) {
                # Resolve all operands with metadata tokens
                Write-Verbose "OpCode Metadata for member: $OpInt"
                try { $MemberInfo = $MethodModule.ResolveMember($OpInt) } catch { $Operand = $null }
                if (!$MemberInfo) { $Operand = $null }
                
                # Retrieve the actual name of the class and method
                if ($MemberInfo.ReflectedType) {
                    $Operand = "{0}.{1}" -f ($MemberInfo.ReflectedType.Fullname), ($MemberInfo.Name)
                } elseif ($MemberInfo -is [Type]) {
                    $Operand = $MemberInfo.GetType().FullName
                } else {
                    $Operand = $MemberInfo.Name
                }
            } elseif ($Type -eq 'InlineString') {
                # Retrieve the referenced string
                $Operand = "`'{0}`'" -f ($MethodModule.ResolveString($OpInt))
            } elseif ($Type -eq 'InlineBrTarget') {
                $Operand = "IL_{0}" -f (($Position + $OpInt + 4).ToString('X4'))
            } else {
                $Operand = $null
            }
        }
        
        if (($OperandLength -gt 0) -and ($OperandLength -ne 4) -and ($Type -ne 'InlineSwitch') -and ($Type -ne 'ShortInlineBrTarget')) {
            # Simply print the hex for all operands with immediate values
            $Operand = "0x{0}" -f (($IL[$Position..($Position+$OperandLength-1)] | ForEach-Object { $_.ToString('X2') }) -join '')
        }
        
        $Instruction = @{
            Position = $InstructionPostion
            Instruction = $Op.Name
            Operand = $Operand
        }
        
        # Return a custom object containing a position, instruction, and fully-qualified operand
        $InstructionObject = New-Object PSObject -Property $Instruction
        $InstructionObject.PSObject.TypeNames.Insert(0, 'IL_INSTRUCTION')
        
        $InstructionObject

        # Adjust the position in the opcode array accordingly
        $Position += $OperandLength
    }
}