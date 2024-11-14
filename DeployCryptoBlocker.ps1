# DeployCryptoBlocker.ps1
# Version: 2.1

Set-StrictMode -Version 3.0

# USER CONFIGURATION

# Define FSRM (File Server Resource Manager) settings
$fileGroupName = "CryptoBlockerGroup"       # Name of the file group to hold monitored extensions
$fileTemplateName = "CryptoBlockerTemplate" # Template name for file screening
$fileTemplateType = "Active"                # Screening type: Active (blocks unauthorized files) or Passive (monitors only)

# Email Notification Configuration
# Commented out section for creating email notifications on violations.
$EmailNotificationAction =  New-FsrmAction -Type Email -MailTo '[Admin Email]' -Subject 'Unauthorized file from the [Violated File Group] file group detected' -Body 'Message=User [Source Io Owner] attempted to save [Source File Path] to [File Screen Path] on the [Server] server. This file is in the [Violated File Group] file group, which is not permitted on the server.'

# Event Log Notification
# Define event log entry when unauthorized files are detected
$eventNotificationAction =  New-FsrmAction -Type Event -RunLimitInterval 5 -EventType Error -Body "User [Source Io Owner] attempted to save [Source File Path] to [File Screen Path] on the [Server] server. This file is in the [Violated File Group] file group, which is not permitted on the server."

# URL for list of known extensions related to ransomware
$KnownExtensionsListURL = "https://raw.githubusercontent.com/DFFspace/CryptoBlocker/master/KnownExtensions.txt"

# Functions

Function New-CBArraySplit
{
    # Splits the list of file extensions to stay within a 4KB limit per entry for FSRM compatibility
    param(
        $Extensions
    )
    # Sort and remove duplicates from extensions array
    $Extensions = $Extensions | Sort-Object -Unique

    # Variables to track working arrays
    $workingArray = @()
    $WorkingArrayIndex = 1
    $LengthOfStringsInWorkingArray = 0

    # Process and split extensions to arrays <= 4KB
    $Extensions | ForEach-Object {
        # If adding the extension exceeds 4KB, output current array and start a new one
        if (($LengthOfStringsInWorkingArray + 1 + $_.Length) -gt 4000) 
        {   
            [PSCustomObject]@{
                index = $WorkingArrayIndex
                FileGroupName = "$Script:FileGroupName$WorkingArrayIndex"
                array = $workingArray
            }
            $workingArray = @($_)
            $LengthOfStringsInWorkingArray = $_.Length
            $WorkingArrayIndex++
        }
        else 
        {
            $workingArray += $_
            $LengthOfStringsInWorkingArray += (1 + $_.Length)
        }
    }

    # Output the final array
    [PSCustomObject]@{
        index = ($WorkingArrayIndex)
        FileGroupName = "$Script:FileGroupName$WorkingArrayIndex"
        array = $workingArray
    }
}

# Main Code

# Server and PowerShell Version Check
$majorVer = [System.Environment]::OSVersion.Version.Major
$minorVer = [System.Environment]::OSVersion.Version.Minor
$powershellVer = $PSVersionTable.PSVersion.Major

# Ensure PowerShell version is 3 or higher
if ($powershellVer -le 2)
{
    Write-Host "`n####"
    Write-Host "ERROR: PowerShell v3 or higher required."
    exit
}

# Check and install FSRM feature if not present
Import-Module ServerManager
if ($majorVer -ge 6)
{
    # Check FSRM status and install if missing
    $checkFSRM = Get-WindowsFeature -Name FS-Resource-Manager
    if (($minorVer -ge 2 -or $majorVer -eq 10) -and $checkFSRM.Installed -ne "True")
    {
        $install = Install-WindowsFeature -Name FS-Resource-Manager -IncludeManagementTools
    }
}

# Load or identify network shares requiring protection
if (Test-Path .\ProtectList.txt)
{
    Move-Item -Path .\ProtectList.txt -Destination $PSScriptRoot\ProtectList.txt -Force
}
if (Test-Path $PSScriptRoot\ProtectList.txt)
{
    $drivesContainingShares = Get-Content $PSScriptRoot\ProtectList.txt | ForEach-Object { $_.Trim() }
}
else
{
    $drivesContainingShares = @(Get-WmiObject Win32_Share | Where-Object { $_.Type -match '0|2147483648' } | Select -ExpandProperty Path | Select -Unique)
}

# Download the list of extensions to monitor
$monitoredExtensions = ((Invoke-WebRequest -Uri $KnownExtensionsListURL -ErrorAction Stop).Content | ConvertFrom-Json).filters

# Process Exclusions from SkipList.txt
if (Test-Path .\SkipList.txt)
{
    Move-Item -Path .\SkipList.txt -Destination $PSScriptRoot\SkipList.txt -Force
}
if (Test-Path $PSScriptRoot\SkipList.txt)
{
    $Exclusions = Get-Content $PSScriptRoot\SkipList.txt | ForEach-Object { $_.Trim() }
    $monitoredExtensions = $monitoredExtensions | Where-Object { $Exclusions -notcontains $_ }
}

# Process additional inclusions from IncludeList.txt
if (Test-Path .\IncludeList.txt)
{
    Move-Item -Path .\IncludeList.txt -Destination $PSScriptRoot\IncludeList.txt -Force
}
if (Test-Path $PSScriptRoot\IncludeList.txt)
{
    $includeExt = Get-Content $PSScriptRoot\IncludeList.txt | ForEach-Object { $_.Trim() }
    $monitoredExtensions = $monitoredExtensions + $includeExt
}

# Create file groups for monitoring, adhering to 4KB limit
$fileGroups = @(New-CBArraySplit $monitoredExtensions)

# Define and configure File Screen Template
$IncludeGroup = $filegroups.Filegroupname
[array]$notifications += $EmailNotificationAction
[array]$notifications += $EventNotificationAction

# Create File Screens for protected shares
$drivesContainingShares | ForEach-Object {
    Remove-FsrmFileScreen -Path $_ -Confirm:$false -ErrorAction SilentlyContinue
    New-FsrmFileScreen -Path $_ -Template $fileTemplateName
}

# Process ExcludeList.txt to add file screen exceptions
if (Test-Path .\ExcludePaths.txt)
{
    Move-Item -Path .\ExcludePaths.txt -Destination $PSScriptRoot\ExcludePaths.txt -Force
}
if (Test-Path $PSScriptRoot\ExcludePaths.txt) {
    Get-Content $PSScriptRoot\ExcludePaths.txt | ForEach-Object {
        If (Test-Path $_) {
            New-FsrmFileScreenException -Path $_ -IncludeGroup ($filegroups.Filegroupname -join ',')
        }
    }
}
