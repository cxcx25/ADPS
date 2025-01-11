
# Get the directory where this script is located
$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path

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

# Import configuration
. (Join-Path -Path $ScriptPath -ChildPath "Config.ps1")

# Create aliases for commonly used functions
Set-Alias -Name adi -Value Get-UserADInfo -Description "Get AD User Info" -Scope Global
Set-Alias -Name unlock -Value Unblock-UserAccount -Description "Unlock AD Account" -Scope Global
Set-Alias -Name resetpwd -Value Reset-UserPassword -Description "Reset AD Password" -Scope Global

# Export functions to make them available in the global scope
Export-ModuleMember -Function Get-UserADInfo, Unblock-UserAccount, Reset-UserPassword, Update-AccountExpiration -Alias *

Write-Host "AD Management Tools loaded successfully!" -ForegroundColor Green
Write-Host "Available commands:" -ForegroundColor Cyan
Write-Host "  adi -Username '<username>' -Domain '<domain>'     (Get user info)" -ForegroundColor Yellow
Write-Host "  unlock -Username '<username>' -Domain '<domain>'  (Unlock account)" -ForegroundColor Yellow
Write-Host "  resetpwd -Username '<username>' -Domain '<domain>' -NewPassword '<password>'  (Reset password)" -ForegroundColor Yellow
