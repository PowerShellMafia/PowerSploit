function Get-VolumeShadowCopy
{
<#
.SYNOPSIS

    Lists the device paths of all local volume shadow copies.

    PowerSploit Function: Get-VolumeShadowCopy
    Author: Matthew Graeber (@mattifestation)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
#>

    $UserIdentity = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())

    if (-not $UserIdentity.IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator'))
    {
        Throw 'You must run Get-VolumeShadowCopy from an elevated command prompt.'
    }

    Get-WmiObject -Namespace root\cimv2 -Class Win32_ShadowCopy | ForEach-Object { $_.DeviceObject }
}

function New-VolumeShadowCopy
{
<#
.SYNOPSIS

    Creates a new volume shadow copy.

    PowerSploit Function: New-VolumeShadowCopy
    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

.DESCRIPTION

    New-VolumeShadowCopy creates a volume shadow copy for the specified volume.

.PARAMETER Volume

    Volume used for the shadow copy. This volume is sometimes referred to as the original volume. 
    The Volume parameter can be specified as a volume drive letter, mount point, or volume globally unique identifier (GUID) name.

.PARAMETER Context

    Context that the provider uses when creating the shadow. The default is "ClientAccessible".

.EXAMPLE

    New-VolumeShadowCopy -Volume C:\

    Description
    -----------
    Creates a new VolumeShadowCopy of the C drive
#>
    Param(
        [Parameter(Mandatory = $True)]
        [ValidatePattern('^\w:\\')]
        [String]
        $Volume,

        [Parameter(Mandatory = $False)]
        [ValidateSet("ClientAccessible")]
        [String]
        $Context = "ClientAccessible"
    )

    $UserIdentity = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())

    if (-not $UserIdentity.IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator'))
    {
        Throw 'You must run Get-VolumeShadowCopy from an elevated command prompt.'
    }

    # Save VSS Service initial state
    $running = (Get-Service -Name VSS).Status

    $class = [WMICLASS]"root\cimv2:win32_shadowcopy"

    $return = $class.create("$Volume", "$Context")

    switch($return.returnvalue)
    {
        1 {Write-Error "Access denied."; break}
        2 {Write-Error "Invalid argument."; break}
        3 {Write-Error "Specified volume not found."; break}
        4 {Write-Error "Specified volume not supported."; break}
        5 {Write-Error "Unsupported shadow copy context."; break}
        6 {Write-Error "Insufficient storage."; break}
        7 {Write-Error "Volume is in use."; break}
        8 {Write-Error "Maximum number of shadow copies reached."; break}
        9 {Write-Error "Another shadow copy operation is already in progress."; break}
        10 {Write-Error "Shadow copy provider vetoed the operation."; break}
        11 {Write-Error "Shadow copy provider not registered."; break}
        12 {Write-Error "Shadow copy provider failure."; break}
        13 {Write-Error "Unknown error."; break}
        default {break}
    }

    # If VSS Service was Stopped at the start, return VSS to "Stopped" state
    if($running -eq "Stopped")
    {
        Stop-Service -Name VSS
    }
}

function Remove-VolumeShadowCopy
{
<#
.SYNOPSIS

    Deletes a volume shadow copy.

    PowerSploit Function: Remove-VolumeShadowCopy
    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

.DESCRIPTION

    Remove-VolumeShadowCopy deletes a volume shadow copy from the system.

.PARAMETER InputObject

    Specifies the Win32_ShadowCopy object to remove

.PARAMETER DevicePath

    Specifies the volume shadow copy 'DeviceObject' path. This path can be retrieved with the Get-VolumeShadowCopy PowerSploit function or with the Win32_ShadowCopy object.

.EXAMPLE

    Get-VolumeShadowCopy | Remove-VolumeShadowCopy

    Description
    -----------
    Removes all volume shadow copy

.EXAMPLE

    Remove-VolumeShadowCopy -DevicePath '\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy4'

    Description
    -----------
    Removes the volume shadow copy at the 'DeviceObject' path \\?\GLOBALROOT\DeviceHarddiskVolumeShadowCopy4
#>
    [CmdletBinding(SupportsShouldProcess = $True)]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [ValidatePattern('^\\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy[0-9]{1,3}$')]
        [String]
        $DevicePath
    )

    PROCESS
    {
        if($PSCmdlet.ShouldProcess("The VolumeShadowCopy at DevicePath $DevicePath will be removed"))
        {
            (Get-WmiObject -Namespace root\cimv2 -Class Win32_ShadowCopy | Where-Object {$_.DeviceObject -eq $DevicePath}).Delete()
        }
    }
}

function Mount-VolumeShadowCopy
{
<#
.SYNOPSIS

    Mounts a volume shadow copy.

    PowerSploit Function: Mount-VolumeShadowCopy
    Author: Matthew Graeber (@mattifestation)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

.DESCRIPTION

    Mount-VolumeShadowCopy mounts a volume shadow copy volume by creating a symbolic link.

.PARAMETER Path

    Specifies the path to which the symbolic link for the mounted volume shadow copy will be saved.

.PARAMETER DevicePath

    Specifies the volume shadow copy 'DeviceObject' path. This path can be retrieved with the Get-VolumeShadowCopy PowerSploit function or with the Win32_ShadowCopy object.

.EXAMPLE

    Get-VolumeShadowCopy | Mount-VolumeShadowCopy -Path C:\VSS

    Description
    -----------
    Create a mount point in 'C:\VSS' for each volume shadow copy volume

.EXAMPLE

    Mount-VolumeShadowCopy -Path C:\VSS -DevicePath '\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy4'

.EXAMPLE

    Get-WmiObject Win32_ShadowCopy | % { $_.DeviceObject -Path C:\VSS -DevicePath $_ }
#>

    Param (
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [ValidatePattern('^\\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy[0-9]{1,3}$')]
        [String[]]
        $DevicePath
    )

    BEGIN
    {
        $UserIdentity = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())

        if (-not $UserIdentity.IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator'))
        {
            Throw 'You must run Get-VolumeShadowCopy from an elevated command prompt.'
        }

        # Validate that the path exists before proceeding
        Get-ChildItem $Path -ErrorAction Stop | Out-Null

        $DynAssembly = New-Object System.Reflection.AssemblyName('VSSUtil')
        $AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('VSSUtil', $False)

        # Define [VSS.Kernel32]::CreateSymbolicLink method using reflection
        # (i.e. none of the forensic artifacts left with using Add-Type)
        $TypeBuilder = $ModuleBuilder.DefineType('VSS.Kernel32', 'Public, Class')
        $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('CreateSymbolicLink',
                                                            'kernel32.dll',
                                                            ([Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static),
                                                            [Reflection.CallingConventions]::Standard,
                                                            [Bool],
                                                            [Type[]]@([String], [String], [UInt32]),
                                                            [Runtime.InteropServices.CallingConvention]::Winapi,
                                                            [Runtime.InteropServices.CharSet]::Auto)
        $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
        $SetLastError = [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
        $SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($DllImportConstructor,
                                                                                         @('kernel32.dll'),
                                                                                         [Reflection.FieldInfo[]]@($SetLastError),
                                                                                         @($true))
        $PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute)

        $Kernel32Type = $TypeBuilder.CreateType()
    }

    PROCESS
    {
        foreach ($Volume in $DevicePath)
        {
            $Volume -match '^\\\\\?\\GLOBALROOT\\Device\\(?<LinkName>HarddiskVolumeShadowCopy[0-9]{1,3})$' | Out-Null
            
            $LinkPath = Join-Path $Path $Matches.LinkName

            if (Test-Path $LinkPath)
            {
                Write-Warning "'$LinkPath' already exists."
                continue
            }

            if (-not $Kernel32Type::CreateSymbolicLink($LinkPath, "$($Volume)\", 1))
            {
                Write-Error "Symbolic link creation failed for '$Volume'."
                continue
            }

            Get-Item $LinkPath
        }
    }

    END
    {

    }
}
