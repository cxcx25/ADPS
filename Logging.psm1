<#
.SYNOPSIS
PowerShell module for domain management utilities
#>
function Write-PsLogError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host "ERROR: $Message" -ForegroundColor Red
}

function Write-PsLogInfo {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host "INFO: $Message" -ForegroundColor Green
}

function Write-PsLogWarning {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host "WARNING: $Message" -ForegroundColor Yellow
}


Export-ModuleMember -Function Write-PsLogInfo, Write-PsLogError, Write-PsLogWarning