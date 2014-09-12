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
    Version: 2.0.0
#>

    $UserIdentity = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())

    if (-not $UserIdentity.IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator'))
    {
        Throw 'You must run Get-VolumeShadowCopy from an elevated command prompt.'
    }

    Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.DeviceObject }
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
    Version: 2.0.0

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