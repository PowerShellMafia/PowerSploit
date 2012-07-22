function Get-DllLoadPath {
<#
.Synopsis

 PowerSploit Module - Get-DllLoadPath
 Author: Matthew Graeber (@mattifestation)
 License: BSD 3-Clause
 
.Description

 Get-DllLoadPath returns the path from which Windows will load a Dll for the given executable.
 
.Parameter ExecutablePath

 Path to the executable from which the Dll would be loaded.

.Parameter DllName

 Name of the Dll in the form 'dllname.dll'.
 
.Example

 PS> Get-DllLoadPath C:\Windows\System32\cmd.exe kernel32.dll
 
 Path
 ----
 C:\Windows\system32\kernel32.dll
 
.Example

 PS> Get-DllLoadPath C:\Windows\SysWOW64\calc.exe Comctl32.dll
 
 Path
 ----
 C:\Windows\SysWOW64\Comctl32.dll

.Outputs

 None or System.Management.Automation.PathInfo
 
.Notes

 This script will not detect if the executable provided intentionally alters the Dll search path via
 LoadLibraryEx, SetDllDirectory, or AddDllDirectory.
 
.Link

 My blog: http://www.exploit-monday.com
 Dll Search Order Reference: http://msdn.microsoft.com/en-us/library/windows/desktop/ms682586%28v=vs.85%29.aspx
#>

    Param (
        [Parameter(Position = 0, Mandatory = $True)] [String] $ExecutablePath,
        [Parameter(Position = 1, Mandatory = $True)] [String] $DllName
    )

    if (!(Test-Path $ExecutablePath)) {
        Write-Warning 'Invalid path or file does not exist.'
        return
    } else {
        $ExecutablePath = Resolve-Path $ExecutablePath
        $ExecutableDirectory = Split-Path $ExecutablePath
    }
    
    if ($DllName.Contains('.dll')) {
        $DllNameShort = $DllName.Split('.')[0]
    } else {
        Write-Warning 'You must provide a proper dll name (i.e. kernel32.dll)'
        return
    }

    function Get-PEArchitecture {

        Param ( [Parameter(Position = 0, Mandatory = $True)] [String] $Path )
        
        # Parse PE header to see if binary was compiled 32 or 64-bit
        $FileStream = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
        
        [Byte[]] $MZHeader = New-Object Byte[](2)
        $FileStream.Read($MZHeader,0,2) | Out-Null
        
        $Header = [System.Text.AsciiEncoding]::ASCII.GetString($MZHeader)
        if ($Header -ne 'MZ') {
            Write-Warning 'Invalid PE header.'
            $FileStream.Close()
            return
        }
        
        # Seek to 0x3c - IMAGE_DOS_HEADER.e_lfanew (i.e. Offset to PE Header)
        $FileStream.Seek(0x3c, [System.IO.SeekOrigin]::Begin) | Out-Null
        
        [Byte[]] $lfanew = New-Object Byte[](4)
        
        # Read offset to the PE Header (will be read in reverse)
        $FileStream.Read($lfanew,0,4) | Out-Null
        $PEOffset = [Int] ('0x{0}' -f (( $lfanew[-1..-4] | % { $_.ToString('X2') } ) -join ''))
        
        # Seek to IMAGE_FILE_HEADER.IMAGE_FILE_MACHINE
        $FileStream.Seek($PEOffset + 4, [System.IO.SeekOrigin]::Begin) | Out-Null
        [Byte[]] $IMAGE_FILE_MACHINE = New-Object Byte[](2)
        
        # Read compiled architecture
        $FileStream.Read($IMAGE_FILE_MACHINE,0,2) | Out-Null
        $Architecture = '{0}' -f (( $IMAGE_FILE_MACHINE[-1..-2] | % { $_.ToString('X2') } ) -join '')
        $FileStream.Close()
        
        if (($Architecture -ne '014C') -and ($Architecture -ne '8664')) {
            Write-Warning 'Invalid PE header or unsupported architecture.'
            return
        }
        
        if ($Architecture -eq '014C') {
            return 'X86'
        } elseif ($Architecture -eq '8664') {
            return 'X64'
        } else {
            return 'OTHER'
        }

    }

    # Check if SafeDllSearch is disabled. Note: The logic of this check will fail in XP SP0/1
    $UnsafeSearch = $False
    $SearchMode = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager').SafeDllSearchMode
    if ($SearchMode -eq 0) { $UnsafeSearch = $True }

    $OSArch = (Get-WmiObject Win32_OperatingSystem -Property OSArchitecture).OSArchitecture
    $PEArch = Get-PEArchitecture $ExecutablePath
    $KnownDlls = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs'

    if ($OSArch -eq '32-bit') {
        $DllDirectory = Resolve-Path $KnownDlls.DllDirectory
    } else {
        if ($PEArch -eq 'X86') {
            $DllDirectory = Resolve-Path $KnownDlls.DllDirectory32
        } else {
            $DllDirectory = Resolve-Path $KnownDlls.DllDirectory
        }
    }

    
    if ($KnownDlls | Get-Member -MemberType NoteProperty | Where-Object { $_.Name -eq $DllNameShort }) {
        $Expression = '$KnownDlls.' + "$DllNameShort"
        $Filename = Invoke-Expression $Expression
        return Resolve-Path (Join-Path $DllDirectory $Filename)
    }
    
    $FoundInAppDirectory = Get-ChildItem (Join-Path $ExecutableDirectory $DllName) -ErrorAction SilentlyContinue
    if ($FoundInAppDirectory) { return Resolve-Path $FoundInAppDirectory.FullName }
    
    if ($UnsafeSearch) {
        $FoundInWorkingDirectory = Get-ChildItem (Join-Path (Get-Location) $DllName) -ErrorAction SilentlyContinue
        if ($FoundInWorkingDirectory) { return Resolve-Path $FoundInWorkingDirectory.FullName }
    }
    
    $FoundInSystemDirectory = Get-ChildItem (Join-Path $DllDirectory $DllName) -ErrorAction SilentlyContinue
    if ($FoundInSystemDirectory) { return Resolve-Path $FoundInSystemDirectory.FullName }
    
    $FoundIn16BitSystemDir = Get-ChildItem "$($Env:windir)\System\$DllName" -ErrorAction SilentlyContinue
    if ($FoundIn16BitSystemDir) { return Resolve-Path $FoundIn16BitSystemDir.FullName }
    
    $FoundInWindowsDirectory = Get-ChildItem "$($Env:windir)\$DllName" -ErrorAction SilentlyContinue
    if ($FoundInWindowsDirectory) { return Resolve-Path $FoundInWindowsDirectory.FullName }
    
    if (!$UnsafeSearch) {
        $FoundInWorkingDirectory = Get-ChildItem (Join-Path (Get-Location) $DllName) -ErrorAction SilentlyContinue
        if ($FoundInWorkingDirectory) { return Resolve-Path $FoundInWorkingDirectory.FullName }
    }
    
    $Env:Path.Split(';') | ForEach-Object {
        if ($_ -match '%(.{1,})%') {
            $TempPath = $_.Replace($Matches[0], [Environment]::GetEnvironmentVariable($Matches[1]))
        } else {
            $TempPath = $_
        }

        $FoundInPathEnvVar = Get-ChildItem (Join-Path $TempPath $DllName) -ErrorAction SilentlyContinue
        if ($FoundInPathEnvVar) { return Resolve-Path $FoundInPathEnvVar.FullName }
    }

}
