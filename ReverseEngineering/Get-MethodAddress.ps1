function Get-MethodAddress
{
<#
.SYNOPSIS

Get the unmanaged function address of a .NET method.

PowerSploit Function: Get-MethodAddress
Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Get-MethodAddress aids in the process of reverse engineering and exploitation by returning an unmanaged function pointer to any .NET method. This method is useful for those interested in seeing what JITed MSIL opcodes look like in their assembly language representation.

For example, here is the MSIL representation of [System.IntPtr].ToPointer:
0x02                     ldarg.0
0x7B,0x53,0x04,0x00,0x04 ldfld void* System.IntPtr::m_value
0x2A                     ret

After calling Get-MethodAddress and inspecting it in WinDbg, here is the x86_64 ASM representation:
C:\PS> Get-MethodAddress ([IntPtr].GetMethod('ToPointer'))
0x000007FF35544CC0

mscorlib_ni+0xd04cc0:
000007ff`35544cc0 488b01    mov     rax,qword ptr [rcx]
000007ff`35544cc3 c3        ret
000007ff`35544cc4 cc        int     3

This MSIL to ASM translation makes sense because all the assembly instructions are doing is dereferencing the pointer in rcx.
 
.PARAMETER MethodInfo

The method whose unmanaged address will be returned.

.EXAMPLE

C:\PS> Get-MethodAddress ([String].GetMethod('Trim', [Type[]]@()))

Description
-----------
Returns the unmanaged address of [System.Object].Trim() method.

.EXAMPLE

C:\PS> [Int].Module.GetTypes().GetMethods() | ForEach-Object {Get-MethodAddress $_ -ErrorAction SilentlyContinue -WarningAction SilentlyContinue}

Description
-----------
Returns an unmanaged address for every method (in which an address can be returned) in mscorlib.

.OUTPUTS

System.String

A hexadecimal representation of the method address.

.NOTES

Not all methods will be able to return an address. For example, methods with implementation flags of AggressiveInlining, Synchronized, or CodeTypeMask will not return an address. Also note that any InternalCall method will return the same pointer every time because the CLR determines its address at runtime.

Lastly, note that the MSIL opcodes used to implement this cmdlet are unverifiable. This means for example, that this technique won't aid exploiting Silverlight applications. :'(

.LINK

http://www.exploit-monday.com/2012/11/Get-MethodAddress.html
#>

    [CmdletBinding()] Param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [System.Reflection.MethodInfo]
        $MethodInfo
    )

    if ($MethodInfo.MethodImplementationFlags -eq 'InternalCall')
    {
        Write-Warning "$($MethodInfo.Name) is an InternalCall method. These methods always point to the same address."
    }

    if ([IntPtr]::Size -eq 4)
    {
        $ReturnType = [UInt32]
    }
    else
    {
        $ReturnType = [UInt64]
    }

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
