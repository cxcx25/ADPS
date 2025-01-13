# Get the directory where this script is located
$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path

# Import config first to set up $global:adConfig
. (Join-Path -Path $ScriptPath -ChildPath "Config.ps1")

# Import required modules
$ModulesToImport = @(
    "UserManagement",
    "DomainUtils",
    "Logging"
)

foreach ($module in $ModulesToImport) {
    $modulePath = Join-Path -Path $ScriptPath -ChildPath "$module.psm1"
    Import-Module $modulePath -Force -Global
}

# Define wrapper functions for common domain-specific operations
function Get-LuxUser { 
    param([Parameter(Mandatory=$true)][string]$Username) 
    Get-UserADInfo -Username $Username -Domain "lux" -AdConfig $global:adConfig 
}

function Get-EssilorUser { 
    param([Parameter(Mandatory=$true)][string]$Username) 
    Get-UserADInfo -Username $Username -Domain "ess" -AdConfig $global:adConfig 
}

function Get-ElUser { 
    param([Parameter(Mandatory=$true)][string]$Username) 
    Get-UserADInfo -Username $Username -Domain "el" -AdConfig $global:adConfig 
}

function Unlock-LuxUser { 
    param([Parameter(Mandatory=$true)][string]$Username) 
    Unblock-UserAccount -Username $Username -Domain "lux" -AdConfig $global:adConfig 
}

function Unlock-EssilorUser { 
    param([Parameter(Mandatory=$true)][string]$Username) 
    Unblock-UserAccount -Username $Username -Domain "ess" -AdConfig $global:adConfig 
}

# Create aliases for commonly used functions
Set-Alias -Name adi -Value Get-UserADInfo -Description "Get AD User Info" -Scope Global
Set-Alias -Name unlock -Value Unblock-UserAccount -Description "Unlock AD Account" -Scope Global
Set-Alias -Name resetpwd -Value Reset-UserPassword -Description "Reset AD Password" -Scope Global
Set-Alias -Name lux -Value Get-LuxUser -Description "Get Luxottica User Info" -Scope Global
Set-Alias -Name ess -Value Get-EssilorUser -Description "Get Essilor User Info" -Scope Global
Set-Alias -Name el -Value Get-ElUser -Description "Get EL User Info" -Scope Global

# Export everything
Export-ModuleMember -Function * -Alias *

# Show available commands
Write-Host "AD Management Tools loaded successfully!" -ForegroundColor Green
Write-Host "`nAvailable Commands:" -ForegroundColor Cyan
Write-Host "  Domain-Specific Functions:" -ForegroundColor Yellow
Write-Host "    Get-LuxUser (luxuser) <username>     : Get Luxottica user info" 
Write-Host "    Get-EssilorUser (essuser) <username> : Get Essilor user info"
Write-Host "    Get-ElUser (eluser) <username>       : Get EL user info"
Write-Host "    Unlock-LuxUser <username>            : Unlock Luxottica user"
Write-Host "    Unlock-EssilorUser <username>        : Unlock Essilor user"
Write-Host "`n  Generic Functions:" -ForegroundColor Yellow
Write-Host "    adi -Username '<username>' -Domain '<domain>'    : Get user info"
Write-Host "    unlock -Username '<username>' -Domain '<domain>' : Unlock account"
Write-Host "    resetpwd -Username '<username>' -Domain '<domain>' -NewPassword '<password>' : Reset password"