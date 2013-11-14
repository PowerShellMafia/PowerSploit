function Find-AVSignature
{
<#
.SYNOPSIS

Locate tiny AV signatures.

PowerSploit Function: Find-AVSignature
Authors: Chris Campbell (@obscuresec) & Matt Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Locates single Byte AV signatures utilizing the same method as DSplit from "class101" on heapoverflow.com.

.PARAMETER Startbyte

Specifies the first byte to begin splitting on.

.PARAMETER Endbyte

Specifies the last byte to split on.

.PARAMETER Interval

Specifies the interval size to split with.

.PARAMETER Path

Specifies the path to the binary you want tested.

.PARAMETER OutPath

Optionally specifies the directory to write the binaries to.

.PARAMETER BufferLen

Specifies the length of the file read buffer .  Defaults to 64KB.  

.PARAMETER Force

Forces the script to continue without confirmation.    

.EXAMPLE

PS C:\> Find-AVSignature -Startbyte 0 -Endbyte max -Interval 10000 -Path c:\test\exempt\nc.exe 
PS C:\> Find-AVSignature -StartByte 10000 -EndByte 20000 -Interval 1000 -Path C:\test\exempt\nc.exe -OutPath c:\test\output\run2 -Verbose
PS C:\> Find-AVSignature -StartByte 16000 -EndByte 17000 -Interval 100 -Path C:\test\exempt\nc.exe -OutPath c:\test\output\run3 -Verbose
PS C:\> Find-AVSignature -StartByte 16800 -EndByte 16900 -Interval 10 -Path C:\test\exempt\nc.exe -OutPath c:\test\output\run4 -Verbose
PS C:\> Find-AVSignature -StartByte 16890 -EndByte 16900 -Interval 1 -Path C:\test\exempt\nc.exe -OutPath c:\test\output\run5 -Verbose

.NOTES

Several of the versions of "DSplit.exe" available on the internet contain malware.

.LINK

http://obscuresecurity.blogspot.com/2012/12/finding-simple-av-signatures-with.html
https://github.com/mattifestation/PowerSploit
http://www.exploit-monday.com/
http://heapoverflow.com/f0rums/project.php?issueid=34&filter=changes&page=2
#>

    [CmdletBinding()] Param(
        [Parameter(Mandatory = $True)]
        [ValidateRange(0,4294967295)]
		[UInt32]
        $StartByte,

        [Parameter(Mandatory = $True)]
        [String]
        $EndByte,

        [Parameter(Mandatory = $True)]
        [ValidateRange(0,4294967295)]
		[UInt32]
        $Interval,

        [String]
		[ValidateScript({Test-Path $_ })]
        $Path = ($pwd.path),

        [String]
        $OutPath = ($pwd),
		
		
		[ValidateRange(1,2097152)]
		[UInt32]
		$BufferLen = 65536,
		
        [Switch] $Force
		
    )

    #test variables
    if (!(Test-Path $Path)) {Throw "File path not found"}
    $Response = $True
    if (!(Test-Path $OutPath)) {
        if ($Force -or ($Response = $psCmdlet.ShouldContinue("The `"$OutPath`" does not exist! Do you want to create the directory?",""))){new-item ($OutPath)-type directory}
	}
    if (!$Response) {Throw "Output path not found"}
    if (!(Get-ChildItem $Path).Exists) {Throw "File not found"}
    [Int32] $FileSize = (Get-ChildItem $Path).Length
    if ($StartByte -gt ($FileSize - 1) -or $StartByte -lt 0) {Throw "StartByte range must be between 0 and $Filesize"}
    [Int32] $MaximumByte = (($FileSize) - 1)
    if ($EndByte -ceq "max") {$EndByte = $MaximumByte}
	
	#Recast $Endbyte into an Integer so that it can be compared properly. 
	[Int32]$EndByte = $EndByte 
	
	#If $Endbyte is greater than the file Length, use $MaximumByte.
    if ($EndByte -gt $FileSize) {$EndByte = $MaximumByte}
	
	#If $Endbyte is less than the $StartByte, use 1 Interval past $StartByte.
	if ($EndByte -lt $StartByte) {$EndByte = $StartByte + $Interval}

	Write-Verbose "StartByte: $StartByte"
	Write-Verbose "EndByte: $EndByte"
	
    #find the filename for the output name
    [String] $FileName = (Split-Path $Path -leaf).Split('.')[0]

    #Calculate the number of binaries
    [Int32] $ResultNumber = [Math]::Floor(($EndByte - $StartByte) / $Interval)
    if (((($EndByte - $StartByte) % $Interval)) -gt 0) {$ResultNumber = ($ResultNumber + 1)}
    
    #Prompt user to verify parameters to avoid writing binaries to the wrong directory
    $Response = $True
    if ( $Force -or ( $Response = $psCmdlet.ShouldContinue("This script will result in $ResultNumber binaries being written to `"$OutPath`"!",
             "Do you want to continue?"))){}
    if (!$Response) {Return}
    
    Write-Verbose "This script will now write $ResultNumber binaries to `"$OutPath`"." 
    [Int32] $Number = [Math]::Floor($Endbyte/$Interval)
    
		#Create a Read Buffer and Stream. 
		#Note: The Filestream class takes advantage of internal .NET Buffering.  We set the default internal buffer to 64KB per http://research.microsoft.com/pubs/64538/tr-2004-136.doc.
		[Byte[]] $ReadBuffer=New-Object byte[] $BufferLen
		[System.IO.FileStream] $ReadStream = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read, $BufferLen)
		
        #write out the calculated number of binaries
        [Int32] $i = 0
        for ($i -eq 0; $i -lt $ResultNumber + 1 ; $i++)
        {
			# If this is the Final Binary, use $EndBytes, Otherwise calculate based on the Interval
			if ($i -eq $ResultNumber) {[Int32]$SplitByte = $EndByte}
			else {[Int32] $SplitByte = (($StartByte) + (($Interval) * ($i)))}
			
			Write-Verbose "Byte 0 -> $($SplitByte)"
			
			#Reset ReadStream to beginning of file
			$ReadStream.Seek(0, [System.IO.SeekOrigin]::Begin) | Out-Null
			
			#Build a new FileStream for Writing
			[String] $outfile = Join-Path $OutPath "$($FileName)_$($SplitByte).bin"
			[System.IO.FileStream] $WriteStream = New-Object System.IO.FileStream($outfile, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None, $BufferLen)
			
			[Int32] $BytesLeft = $SplitByte
			Write-Verbose "$($WriteStream.name)"
			
			#Write Buffer Length to the Writing Stream until the bytes left is smaller than the buffer 
			while ($BytesLeft -gt $BufferLen){
				[Int32]$count = $ReadStream.Read($ReadBuffer, 0, $BufferLen)
				$WriteStream.Write($ReadBuffer, 0, $count)
				$BytesLeft = $BytesLeft - $count
			}
			
			#Write the remaining bytes to the file 
			do {
				[Int32]$count = $ReadStream.Read($ReadBuffer, 0, $BytesLeft)
				$WriteStream.Write($ReadBuffer, 0, $count)
				$BytesLeft = $BytesLeft - $count			
			}
			until ($BytesLeft -eq 0)
			$WriteStream.Close()
			$WriteStream.Dispose()
        }
        Write-Verbose "Files written to disk. Flushing memory."
        $ReadStream.Dispose()
        
		#During testing using large binaries, memory usage was excessive so lets fix that
        [System.GC]::Collect()
        Write-Verbose "Completed!"
}
