### PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid reverse engineers, forensic analysts, and penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts:

## CodeExecution

**Execute code on a target machine.**

#### `Invoke-DllInjection`

Injects a Dll into the process ID of your choosing.

#### `Invoke-ReflectivePEInjection`

Reflectively loads a Windows PE file (DLL/EXE) in to the powershell process, or reflectively injects a DLL in to a remote process.

#### `Invoke-Shellcode`

Injects shellcode into the process ID of your choosing or within PowerShell locally.

#### `Invoke-ShellcodeMSIL`

Execute shellcode within the context of the running PowerShell process without making any Win32 function calls.

## ScriptModification

**Modify and/or prepare scripts for execution on a compromised machine.**

#### `Out-EncodedCommand`

Compresses, Base-64 encodes, and generates command-line output for a PowerShell payload script.

#### `Out-CompressedDll`

Compresses, Base-64 encodes, and outputs generated code to load a managed dll in memory.

#### `Out-EncryptedScript`

Encrypts text files/scripts.

#### `Remove-Comments`

Strips comments and extra whitespace from a script. 

## Persistence

**Add persistence capabilities to a PowerShell script**

#### `New-UserPersistenceOption`

Configure user-level persistence options for the Add-Persistence function.

#### `New-ElevatedPersistenceOption`

Configure elevated persistence options for the Add-Persistence function.

#### `Add-Persistence`

Add persistence capabilities to a script.

## PETools

**Parse/manipulate Windows portable executables.**

#### `Get-PEHeader`

An in-memory and on-disk PE parsing utility.

#### `Get-ObjDump`

Displays information about one or more Windows object files.

#### `Get-LibSymbols`

Displays symbolic information from Windows lib files.

#### `Get-DllLoadPath`

Returns the path from which Windows will load a Dll for the given executable.

## Capstone

**A PowerShell binding for the Capstone Engine disassembly framework.**

#### `Get-CSDisassembly`

Disassembles a byte array using the Capstone Engine disassembly framework.

## ReverseEngineering

**Tools to aid in reverse engineering.**

#### `Get-PEB`

Returns the process environment block (PEB) of a process.

#### `Get-ILDisassembly`

Disassembles a raw MSIL byte array passed in from a MethodInfo object in a manner similar to that of Ildasm.

#### `Get-NtSystemInformation`

A utility that calls and parses the output of the ntdll!NtQuerySystemInformation function. This utility can be used to query internal OS information that is typically not made visible to a user.

#### `Get-StructFromMemory`

Marshals data from an unmanaged block of memory in an arbitrary process to a newly allocated managed object of the specified type.

#### `Get-Member`

A proxy function used to extend the built-in Get-Member cmdlet. It adds the '-Private' parameter allowing you to display non-public .NET members

#### `Get-Strings`

Dumps strings from files in both Unicode and Ascii. This cmdlet replicates the functionality of strings.exe from Sysinternals.

#### `ConvertTo-String`

Converts the bytes of a file to a string that has a 1-to-1 mapping back to the file's original bytes. ConvertTo-String is useful for performing binary regular expressions.

#### `Get-MethodAddress`

Get the unmanaged function address of a .NET method.

#### `Register-ProcessModuleTrace`

Starts a trace of loaded process modules

#### `Get-ProcessModuleTrace`

Displays the process modules that have been loaded since the call to Register-ProcessModuleTrace

#### `Unregister-ProcessModuleTrace`

Stops the running process module trace

#### `Get-Entropy`

Calculates the entropy of a file or byte array.

## AntivirusBypass

**AV doesn't stand a chance against PowerShell!**

#### `Find-AVSignature`

Locates single Byte AV signatures utilizing the same method as DSplit from "class101".

## Exfiltration

**All your data belong to me!**

#### `Invoke-TokenManipulation`

Lists available logon tokens. Creates processes with other users logon tokens, and impersonates logon tokens in the current thread.

#### `Invoke-CredentialInjection`

Create logons with clear-text credentials without triggering a suspicious Event ID 4648 (Explicit Credential Logon).

#### `Invoke-NinjaCopy`

Copies a file from an NTFS partitioned volume by reading the raw volume and parsing the NTFS structures.

#### `Invoke-Mimikatz`

Reflectively loads Mimikatz 1.0 in memory using PowerShell. Can be used to dump credentials without writing anything to disk. Can be used for any functionality provided with Mimikatz.

#### `Get-Keystrokes`

Logs keys pressed, time and the active window.

#### `Get-GPPPassword`

Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences.

#### `Get-TimedScreenshot`

A function that takes screenshots at a regular interval and saves them to a folder.

#### `Get-VolumeShadowCopy`

Lists the device paths of all local volume shadow copies.

#### `Mount-VolumeShadowCopy`

Mounts a volume shadow copy.

#### `Get-VaultCredential`

Displays Windows vault credential objects including cleartext web credentials.

#### `Out-Minidump`

Generates a full-memory minidump of a process.

## Mayhem

**Cause general mayhem with PowerShell.**

#### `Set-MasterBootRecord`

Proof of concept code that overwrites the master boot record with the
 message of your choice.

#### `Set-CriticalProcess`

Causes your machine to blue screen upon exiting PowerShell.

## Recon

**Tools to aid in the reconnaissance phase of a penetration test.**

#### `Invoke-Portscan`

Does a simple port scan using regular sockets, based (pretty) loosely on nmap.

#### `Get-HttpStatus`

Returns the HTTP Status Codes and full URL for specified paths when provided with a dictionary file.

#### `Invoke-ReverseDnsLookup`

Scans an IP address range for DNS PTR records. This script is useful for performing DNS reconnaissance prior to conducting an authorized penetration test.

## Recon\Dictionaries

**A collection of dictionaries used to aid in the reconnaissance phase of a penetration test. Dictionaries were taken from the following sources.**

* admin.txt - <http://cirt.net/nikto2/>
* generic.txt - <http://sourceforge.net/projects/yokoso/files/yokoso-0.1/>
* sharepoint.txt - <http://www.stachliu.com/resources/tools/sharepoint-hacking-diggity-project/>

## License

The PowerSploit project and all individual scripts are under the [BSD 3-Clause license](https://raw.github.com/mattifestation/PowerSploit/master/LICENSE) unless explicitly noted otherwise.

## Usage

Refer to the comment-based help in each individual script for detailed usage information.

To install this module, drop the entire PowerSploit folder into one of your module directories. The default PowerShell module paths are listed in the $Env:PSModulePath environment variable.

The default per-user module path is: "$Env:HomeDrive$Env:HOMEPATH\Documents\WindowsPowerShell\Modules"
The default computer-level module path is: "$Env:windir\System32\WindowsPowerShell\v1.0\Modules"

To use the module, type `Import-Module PowerSploit`

To see the commands imported, type `Get-Command -Module PowerSploit`

If you're running PowerShell v3 and you want to remove the annoying 'Do you really want to run scripts downloaded from the Internet' warning, once you've placed PowerSploit into your module path, run the following one-liner:
`$Env:PSModulePath.Split(';') |
 % { if ( Test-Path (Join-Path $_ PowerSploit) )
 {Get-ChildItem $_ -Recurse | Unblock-File} }`

For help on each individual command, Get-Help is your friend.

Note: The tools contained within this module were all designed such that they can be run individually. Including them in a module simply lends itself to increased portability.

## Script Style Guide

**For all contributors and future contributors to PowerSploit, I ask that you follow this style guide when writing your scripts/modules.**

* Avoid Write-Host **at all costs**. PowerShell functions/cmdlets are not command-line utilities! Pull requests containing code that uses Write-Host will not be considered. You should output custom objects instead. For more information on creating custom objects, read these articles:
   * <http://blogs.technet.com/b/heyscriptingguy/archive/2011/05/19/create-custom-objects-in-your-powershell-script.aspx>
   * <http://technet.microsoft.com/en-us/library/ff730946.aspx>

* If you want to display relevant debugging information to the screen, use Write-Verbose. The user can always just tack on '-Verbose'.

* Always provide descriptive, comment-based help for every script. Also, be sure to include your name and a BSD 3-Clause license (unless there are extenuating circumstances that prevent the application of the BSD license).

* Make sure all functions follow the proper PowerShell verb-noun agreement. Use Get-Verb to list the default verbs used by PowerShell.

* I prefer that variable names be capitalized and be as descriptive as possible.

* Provide logical spacing in between your code. Indent your code to make it more readable.

* If you find yourself repeating code, write a function.

* Catch all anticipated errors and provide meaningful output. If you have an error that should stop execution of the script, use 'Throw'. If you have an error that doesn't need to stop execution, use Write-Error.

* If you are writing a script that interfaces with the Win32 API, do not compile C# code unless absolutely necessary. It is imperative that nothing aside from the script touches the disk.

* Do not use hardcoded paths. A script should be useable right out of the box. No one should have to modify the code unless they want to.

* I don't want any v3 dependencies right now. In fact, it would be ideal to use `Set-StrictMode -Version 2.0` to ensure you are conforming to PowerShell v2 best practices.

* Use positional parameters and make parameters mandatory when it makes sense to do so. For example, I'm looking for something like the following:
   * `[Parameter(Position = 0, Mandatory = $True)]`

* Don't use any aliases unless it makes sense for receiving pipeline input. They make code more difficult to read for people who are unfamiliar with a particular alias.

* Don't let commands run on for too long. For example, a pipeline is a natural place for a line break.

* Don't go overboard with inline comments. Only use them when certain aspects of the code might be confusing to a reader.

* Use Out-Null to suppress unwanted/irrelevant output.

* Only use .NET code when absolutely necessary.

* Use the Write-Output keyword when returning an object from a function. I know it's not necessary but it makes the code more readable.

* Use default values for your parameters when it makes sense. Ideally, you want a script that will work without requiring any parameters.

* Scripts that are intended to run on a remote machine should be self-contained and not rely upon any additional scripts. Scripts that are designed to run on your host machine can have dependencies on other scripts.

* If a script creates complex custom objects, include a ps1xml file that will properly format the object's output.