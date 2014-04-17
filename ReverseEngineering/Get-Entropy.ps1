function Get-Entropy
{
<#
.SYNOPSIS

    Calculates the entropy of a file or byte array.

    PowerSploit Function: Get-Entropy
    Author: Matthew Graeber (@mattifestation)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

.PARAMETER ByteArray

    Specifies the byte array containing the data from which entropy will be calculated.

.PARAMETER FilePath

    Specifies the path to the input file from which entropy will be calculated.

.EXAMPLE

    C:\PS>Get-Entropy -FilePath C:\Windows\System32\kernel32.dll

.EXAMPLE

    C:\PS>ls C:\Windows\System32\*.dll | % { Get-Entropy -FilePath $_ }

.EXAMPLE

    C:\PS>$RandArray = New-Object Byte[](10000)
    C:\PS>foreach ($Offset in 0..9999) { $RandArray[$Offset] = [Byte] (Get-Random -Min 0 -Max 256) }
    C:\PS>$RandArray | Get-Entropy

    Description
    -----------
    Calculates the entropy of a large array containing random bytes.

.EXAMPLE

    C:\PS> 0..255 | Get-Entropy

    Description
    -----------
    Calculates the entropy of 0-255. This should equal exactly 8.

.OUTPUTS

    System.Double

    Get-Entropy outputs a double representing the entropy of the byte array.

.LINK

    http://www.exploit-monday.com
#>

    [CmdletBinding()] Param (
        [Parameter(Mandatory = $True, Position = 0, ValueFromPipeline = $True, ParameterSetName = 'Bytes')]
        [ValidateNotNullOrEmpty()]
        [Byte[]]
        $ByteArray,

        [Parameter(Mandatory = $True, Position = 0, ParameterSetName = 'File')]
        [ValidateNotNullOrEmpty()]
        [IO.FileInfo]
        $FilePath
    )

    BEGIN
    {
        $FrequencyTable = @{}
        $ByteArrayLength = 0
    }

    PROCESS
    {
        if ($PsCmdlet.ParameterSetName -eq 'File')
        {
            $ByteArray = [IO.File]::ReadAllBytes($FilePath.FullName)
        }

        foreach ($Byte in $ByteArray)
        {
            $FrequencyTable[$Byte]++
            $ByteArrayLength++
        }
    }

    END
    {
        $Entropy = 0.0

        foreach ($Byte in 0..255)
        {
            $ByteProbability = ([Double] $FrequencyTable[[Byte]$Byte]) / $ByteArrayLength
            if ($ByteProbability -gt 0)
            {
                $Entropy += -$ByteProbability * [Math]::Log($ByteProbability, 2)
            }
        }

        Write-Output $Entropy
    }
}