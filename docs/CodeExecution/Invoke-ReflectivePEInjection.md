# Invoke-ReflectivePEInjection

## SYNOPSIS
This script has two modes.
It can reflectively load a DLL/EXE in to the PowerShell process,
or it can reflectively load a DLL in to a remote process.
These modes have different parameters and constraints,
please lead the Notes section (GENERAL NOTES) for information on how to use them.

1.)Reflectively loads a DLL or EXE in to memory of the Powershell process.
Because the DLL/EXE is loaded reflectively, it is not displayed when tools are used to list the DLLs of a running process.

This tool can be run on remote servers by supplying a local Windows PE file (DLL/EXE) to load in to memory on the remote system,
this will load and execute the DLL/EXE in to memory without writing any files to disk.

2.) Reflectively load a DLL in to memory of a remote process.
As mentioned above, the DLL being reflectively loaded won't be displayed when tools are used to list DLLs of the running remote process.

This is probably most useful for injecting backdoors in SYSTEM processes in Session0.
Currently, you cannot retrieve output
from the DLL.
The script doesn't wait for the DLL to complete execution, and doesn't make any effort to cleanup memory in the
remote process.

PowerSploit Function: Invoke-ReflectivePEInjection  
Author: Joe Bialek, Twitter: @JosephBialek  
Code review and modifications: Matt Graeber, Twitter: @mattifestation  
License: BSD 3-Clause  
Required Dependencies: None  
Optional Dependencies: None

## SYNTAX

```
Invoke-ReflectivePEInjection [-PEBytes] <Byte[]> [[-ComputerName] <String[]>] [[-FuncReturnType] <String>]
 [[-ExeArgs] <String>] [[-ProcId] <Int32>] [[-ProcName] <String>] [-ForceASLR] [-DoNotZeroMZ]
```

## DESCRIPTION
Reflectively loads a Windows PE file (DLL/EXE) in to the powershell process, or reflectively injects a DLL in to a remote process.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Load DemoDLL and run the exported function WStringFunc on Target.local, print the wchar_t* returned by WStringFunc().
```

$PEBytes = \[IO.File\]::ReadAllBytes('DemoDLL.dll')
Invoke-ReflectivePEInjection -PEBytes $PEBytes -FuncReturnType WString -ComputerName Target.local

### -------------------------- EXAMPLE 2 --------------------------
```
Load DemoDLL and run the exported function WStringFunc on all computers in the file targetlist.txt. Print
```

the wchar_t* returned by WStringFunc() from all the computers.
$PEBytes = \[IO.File\]::ReadAllBytes('DemoDLL.dll')
Invoke-ReflectivePEInjection -PEBytes $PEBytes -FuncReturnType WString -ComputerName (Get-Content targetlist.txt)

### -------------------------- EXAMPLE 3 --------------------------
```
Load DemoEXE and run it locally.
```

$PEBytes = \[IO.File\]::ReadAllBytes('DemoEXE.exe')
Invoke-ReflectivePEInjection -PEBytes $PEBytes -ExeArgs "Arg1 Arg2 Arg3 Arg4"

### -------------------------- EXAMPLE 4 --------------------------
```
Load DemoEXE and run it locally. Forces ASLR on for the EXE.
```

$PEBytes = \[IO.File\]::ReadAllBytes('DemoEXE.exe')
Invoke-ReflectivePEInjection -PEBytes $PEBytes -ExeArgs "Arg1 Arg2 Arg3 Arg4" -ForceASLR

### -------------------------- EXAMPLE 5 --------------------------
```
Refectively load DemoDLL_RemoteProcess.dll in to the lsass process on a remote computer.
```

$PEBytes = \[IO.File\]::ReadAllBytes('DemoDLL_RemoteProcess.dll')
Invoke-ReflectivePEInjection -PEBytes $PEBytes -ProcName lsass -ComputerName Target.Local

## PARAMETERS

### -PEBytes
A byte array containing a DLL/EXE to load and execute.

```yaml
Type: Byte[]
Parameter Sets: (All)
Aliases: 

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ComputerName
Optional, an array of computernames to run the script on.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases: 

Required: False
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -FuncReturnType
Optional, the return type of the function being called in the DLL.
Default: Void
    Options: String, WString, Void.
See notes for more information.
    IMPORTANT: For DLLs being loaded remotely, only Void is supported.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: 3
Default value: Void
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExeArgs
Optional, arguments to pass to the executable being reflectively loaded.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: 4
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ProcId
Optional, the process ID of the remote process to inject the DLL in to.
If not injecting in to remote process, ignore this.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases: 

Required: False
Position: 5
Default value: 0
Accept pipeline input: False
Accept wildcard characters: False
```

### -ProcName
Optional, the name of the remote process to inject the DLL in to.
If not injecting in to remote process, ignore this.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: 6
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ForceASLR
Optional, will force the use of ASLR on the PE being loaded even if the PE indicates it doesn't support ASLR.
Some PE's will work with ASLR even
    if the compiler flags don't indicate they support it.
Other PE's will simply crash.
Make sure to test this prior to using.
Has no effect when
    loading in to a remote process.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -DoNotZeroMZ
Optional, will not wipe the MZ from the first two bytes of the PE.
This is to be used primarily for testing purposes and to enable loading the same PE with Invoke-ReflectivePEInjection more than once.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

## INPUTS

## OUTPUTS

## NOTES
GENERAL NOTES:
The script has 3 basic sets of functionality:
1.) Reflectively load a DLL in to the PowerShell process
    -Can return DLL output to user when run remotely or locally.
    -Cleans up memory in the PS process once the DLL finishes executing.
    -Great for running pentest tools on remote computers without triggering process monitoring alerts.
    -By default, takes 3 function names, see below (DLL LOADING NOTES) for more info.
2.) Reflectively load an EXE in to the PowerShell process.
    -Can NOT return EXE output to user when run remotely.
If remote output is needed, you must use a DLL.
CAN return EXE output if run locally.
    -Cleans up memory in the PS process once the DLL finishes executing.
    -Great for running existing pentest tools which are EXE's without triggering process monitoring alerts.
3.) Reflectively inject a DLL in to a remote process.
    -Can NOT return DLL output to the user when run remotely OR locally.
    -Does NOT clean up memory in the remote process if/when DLL finishes execution.
    -Great for planting backdoor on a system by injecting backdoor DLL in to another processes memory.
    -Expects the DLL to have this function: void VoidFunc().
This is the function that will be called after the DLL is loaded.

DLL LOADING NOTES:

PowerShell does not capture an applications output if it is output using stdout, which is how Windows console apps output.
If you need to get back the output from the PE file you are loading on remote computers, you must compile the PE file as a DLL, and have the DLL
return a char* or wchar_t*, which PowerShell can take and read the output from.
Anything output from stdout which is run using powershell
remoting will not be returned to you.
If you just run the PowerShell script locally, you WILL be able to see the stdout output from
applications because it will just appear in the console window.
The limitation only applies when using PowerShell remoting.

For DLL Loading:
Once this script loads the DLL, it calls a function in the DLL.
There is a section near the bottom labeled "YOUR CODE GOES HERE"
I recommend your DLL take no parameters.
I have prewritten code to handle functions which take no parameters are return
the following types: char*, wchar_t*, and void.
If the function returns char* or wchar_t* the script will output the
returned data.
The FuncReturnType parameter can be used to specify which return type to use.
The mapping is as follows:
wchar_t*   : FuncReturnType = WString
char*      : FuncReturnType = String
void       : Default, don't supply a FuncReturnType

For the whcar_t* and char_t* options to work, you must allocate the string to the heap.
Don't simply convert a string
using string.c_str() because it will be allocaed on the stack and be destroyed when the DLL returns.

The function name expected in the DLL for the prewritten FuncReturnType's is as follows:
WString    : WStringFunc
String     : StringFunc
Void       : VoidFunc

These function names ARE case sensitive.
To create an exported DLL function for the wstring type, the function would
be declared as follows:
extern "C" __declspec( dllexport ) wchar_t* WStringFunc()


If you want to use a DLL which returns a different data type, or which takes parameters, you will need to modify
this script to accomodate this.
You can find the code to modify in the section labeled "YOUR CODE GOES HERE".

Find a DemoDLL at: https://github.com/clymb3r/PowerShell/tree/master/Invoke-ReflectiveDllInjection

## RELATED LINKS

[http://clymb3r.wordpress.com/2013/04/06/reflective-dll-injection-with-powershell/

Blog on modifying mimikatz for reflective loading: http://clymb3r.wordpress.com/2013/04/09/modifying-mimikatz-to-be-loaded-using-invoke-reflectivedllinjection-ps1/
Blog on using this script as a backdoor with SQL server: http://www.casaba.com/blog/](http://clymb3r.wordpress.com/2013/04/06/reflective-dll-injection-with-powershell/

Blog on modifying mimikatz for reflective loading: http://clymb3r.wordpress.com/2013/04/09/modifying-mimikatz-to-be-loaded-using-invoke-reflectivedllinjection-ps1/
Blog on using this script as a backdoor with SQL server: http://www.casaba.com/blog/)

