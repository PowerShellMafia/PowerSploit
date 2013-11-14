function Remove-Comments
{
<#
.SYNOPSIS

Strips comments and extra whitespace from a script.

PowerSploit Function: Remove-Comments
Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Remove-Comments strips out comments and unnecessary whitespace from a script. This is best used in conjunction with Out-EncodedCommand when the size of the script to be encoded might be too big.

A major portion of this code was taken from the Lee Holmes' Show-ColorizedContent script. You rock, Lee!

.PARAMETER ScriptBlock

Specifies a scriptblock containing your script.

.PARAMETER Path

Specifies the path to your script.

.EXAMPLE

C:\PS> $Stripped = Remove-Comments -Path .\ScriptWithComments.ps1

.EXAMPLE

C:\PS> Remove-Comments -ScriptBlock {
### This is my awesome script. My documentation is beyond reproach!
      Write-Host 'Hello, World!' ### Write 'Hello, World' to the host
### End script awesomeness
}

Write-Host 'Hello, World!'

.EXAMPLE

C:\PS> Remove-Comments -Path Inject-Shellcode.ps1 | Out-EncodedCommand

Description
-----------
Removes extraneous whitespace and comments from Inject-Shellcode (which is notoriously large) and pipes the output to Out-EncodedCommand.

.INPUTS

System.String, System.Management.Automation.ScriptBlock

Accepts either a string containing the path to a script or a scriptblock.

.OUTPUTS

System.Management.Automation.ScriptBlock

Remove-Comments returns a scriptblock. Call the ToString method to convert a scriptblock to a string, if desired.

.LINK

http://www.exploit-monday.com
http://www.leeholmes.com/blog/2007/11/07/syntax-highlighting-in-powershell/
#>

    [CmdletBinding( DefaultParameterSetName = 'FilePath' )] Param (
        [Parameter(Position = 0, Mandatory = $True, ParameterSetName = 'FilePath' )]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        [Parameter(Position = 0, ValueFromPipeline = $True, Mandatory = $True, ParameterSetName = 'ScriptBlock' )]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]
        $ScriptBlock
    )

    Set-StrictMode -Version 2

    if ($PSBoundParameters['Path'])
    {
        Get-ChildItem $Path -ErrorAction Stop | Out-Null
        $ScriptBlockString = [IO.File]::ReadAllText((Resolve-Path $Path))
        $ScriptBlock = [ScriptBlock]::Create($ScriptBlockString)
    }
    else
    {
        # Convert the scriptblock to a string so that it can be referenced with array notation
        $ScriptBlockString = $ScriptBlock.ToString()
    }

    # Tokenize the scriptblock and return all tokens except for comments
    $Tokens = [System.Management.Automation.PSParser]::Tokenize($ScriptBlock, [Ref] $Null) | Where-Object { $_.Type -ne 'Comment' }

    $StringBuilder = New-Object Text.StringBuilder

    # The majority of the remaining code comes from Lee Holmes' Show-ColorizedContent script.
    $CurrentColumn = 1
    $NewlineCount = 0
    foreach($CurrentToken in $Tokens)
    {
        # Now output the token
        if(($CurrentToken.Type -eq 'NewLine') -or ($CurrentToken.Type -eq 'LineContinuation'))
        {
            $CurrentColumn = 1
            # Only insert a single newline. Sequential newlines are ignored in order to save space.
            if ($NewlineCount -eq 0)
            {
                $StringBuilder.AppendLine() | Out-Null
            }
            $NewlineCount++
        }
        else
        {
            $NewlineCount = 0

            # Do any indenting
            if($CurrentColumn -lt $CurrentToken.StartColumn)
            {
                # Insert a single space in between tokens on the same line. Extraneous whiltespace is ignored.
                if ($CurrentColumn -ne 1)
                {
                    $StringBuilder.Append(' ') | Out-Null
                }
            }

            # See where the token ends
            $CurrentTokenEnd = $CurrentToken.Start + $CurrentToken.Length - 1

            # Handle the line numbering for multi-line strings
            if(($CurrentToken.Type -eq 'String') -and ($CurrentToken.EndLine -gt $CurrentToken.StartLine))
            {
                $LineCounter = $CurrentToken.StartLine
                $StringLines = $(-join $ScriptBlockString[$CurrentToken.Start..$CurrentTokenEnd] -split '`r`n')

                foreach($StringLine in $StringLines)
                {
                    $StringBuilder.Append($StringLine) | Out-Null
                    $LineCounter++
                }
            }
            # Write out a regular token
            else
            {
                $StringBuilder.Append((-join $ScriptBlockString[$CurrentToken.Start..$CurrentTokenEnd])) | Out-Null
            }

            # Update our position in the column
            $CurrentColumn = $CurrentToken.EndColumn
        }
    }

    Write-Output ([ScriptBlock]::Create($StringBuilder.ToString()))
}
