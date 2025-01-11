<#
.SYNOPSIS
PowerShell module for consistent logging functionality
#>

# Script configuration
$script:Config = @{
    LogPath = Join-Path -Path $PSScriptRoot -ChildPath "ADManagement.log"
}

<#
.SYNOPSIS
Writes a status message to the console and the log file.
#>
function Write-StatusMessage {
    param (
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Type = 'Info'
    )
    
    switch ($Type) {
        'Info'    { Write-Host $Message -ForegroundColor Cyan }
        'Success' { Write-Host $Message -ForegroundColor Green }
        'Warning' { Write-Host $Message -ForegroundColor Yellow }
        'Error'   { Write-Host $Message -ForegroundColor Red }
    }
    
    $logMessage = "[$([DateTime]::Now.ToString('yyyy-MM-dd HH:mm:ss'))] [$Type] $Message"
    Add-Content -Path $script:Config.LogPath -Value $logMessage
}

<#
.SYNOPSIS
Writes an informational log message
#>
function Write-PsLogInfo {
    param([string]$Message)
    Write-StatusMessage -Message $Message -Type 'Info'
}

<#
.SYNOPSIS
Writes a warning log message
#>
function Write-PsLogWarning {
    param([string]$Message)
    Write-StatusMessage -Message $Message -Type 'Warning'
}

<#
.SYNOPSIS
Writes an error log message
#>
function Write-PsLogError {
    param([string]$Message)
    Write-StatusMessage -Message $Message -Type 'Error'
}

<#
.SYNOPSIS
Writes a success log message
#>
function Write-PsLogSuccess {
    param([string]$Message)
    Write-StatusMessage -Message $Message -Type 'Success'
}

# Export all functions
Export-ModuleMember -Function Write-StatusMessage, Write-PsLogInfo, Write-PsLogWarning, Write-PsLogError, Write-PsLogSuccess