# Get the directory where this script is located
$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path

# Import config first to set up $global:adConfig
. (Join-Path -Path $ScriptPath -ChildPath "Config.ps1")

# Import required modules
$ModulesToImport = @(
    "CredentialManagement",
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
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$Username
    ) 
    Get-UserADInfo -UserNames $Username -Domain "lux"
}

function Get-EssilorUser { 
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$Username
    ) 
    Get-UserADInfo -UserNames $Username -Domain "ess"
}

function Get-ElUser { 
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$Username
    ) 
    Get-UserADInfo -UserNames $Username -Domain "el"
}

function Unlock-LuxUsers { 
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$Username
    ) 
    Unblock-UserAccount -Username $Username -Domain "lux"
}

function Unlock-EssilorUsers { 
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$Username
    ) 
    Unblock-UserAccount -Username $Username -Domain "ess"
}

function Reset-LuxUserPasswords {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$Username,
        
        [Parameter(Mandatory=$true)]
        [string]$NewPassword
    )
    Reset-UserPassword -Username $Username -Domain "lux" -NewPassword $NewPassword
}

function Reset-EssilorUserPasswords {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$Username,
        
        [Parameter(Mandatory=$true)]
        [string]$NewPassword
    )
    Reset-UserPassword -Username $Username -Domain "ess" -NewPassword $NewPassword
}

function Update-LuxAccountExpirations {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$Username,
        
        [Parameter(Mandatory=$true)]
        [int]$DaysToExtend
    )
    Update-AccountExpiration -Username $Username -Domain "lux" -DaysToExtend $DaysToExtend
}

function Update-EssilorAccountExpirations {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$Username,
        
        [Parameter(Mandatory=$true)]
        [int]$DaysToExtend
    )
    Update-AccountExpiration -Username $Username -Domain "ess" -DaysToExtend $DaysToExtend
}

# Create aliases for commonly used functions
Set-Alias -Name lux -Value Get-LuxUser -Description "Get Luxottica User Info" -Scope Global
Set-Alias -Name ess -Value Get-EssilorUser -Description "Get Essilor User Info" -Scope Global
Set-Alias -Name el -Value Get-ElUser -Description "Get EL User Info" -Scope Global
Set-Alias -Name ulux -Value Unlock-LuxUsers -Description "Unlock Luxottica Users" -Scope Global
Set-Alias -Name uess -Value Unlock-EssilorUsers -Description "Unlock Essilor Users" -Scope Global

# Show available commands
Write-Host "AD Management Tools loaded successfully!" -ForegroundColor Green
Write-Host "`nAvailable Commands:" -ForegroundColor Cyan
Write-Host "  Domain-Specific Functions:" -ForegroundColor Yellow
Write-Host "    Get-LuxUser (lux) <usernames>     : Get Luxottica user info (supports multiple users)" 
Write-Host "    Get-EssilorUser (ess) <usernames> : Get Essilor user info (supports multiple users)"
Write-Host "    Get-ElUser (el) <usernames>       : Get EL user info (supports multiple users)"
Write-Host "    Unlock-LuxUsers (ulux) <usernames>        : Unlock Luxottica users"
Write-Host "    Unlock-EssilorUsers (uess) <usernames>    : Unlock Essilor users"
Write-Host "    Reset-LuxUserPasswords <usernames> <newpassword>     : Reset Luxottica user passwords"
Write-Host "    Reset-EssilorUserPasswords <usernames> <newpassword> : Reset Essilor user passwords"
Write-Host "    Update-LuxAccountExpirations <usernames> <days>      : Extend Luxottica account expirations"
Write-Host "    Update-EssilorAccountExpirations <usernames> <days>  : Extend Essilor account expirations"

Write-Host "`n  Generic Functions:" -ForegroundColor Yellow
Write-Host "    Get-UserADInfo -UserNames '<usernames>' -Domain '<domain>'    : Get user info"
Write-Host "    Unblock-UserAccount -Username '<usernames>' -Domain '<domain>'  : Unlock account"
Write-Host "    Reset-UserPassword -Username '<usernames>' -Domain '<domain>' -NewPassword '<password>'  : Reset password"
Write-Host "    Update-AccountExpiration -Username '<usernames>' -Domain '<domain>' -DaysToExtend <days>  : Extend account"

Write-Host "`nExample Usage:" -ForegroundColor Yellow
Write-Host "    Get-LuxUser 'user1','user2','user3'    : Get info for multiple Luxottica users"
Write-Host "    Unlock-LuxUsers 'user1','user2'        : Unlock multiple Luxottica users"
Write-Host "    Reset-LuxUserPasswords 'user1','user2' 'NewP@ssw0rd'  : Reset passwords for multiple users"
