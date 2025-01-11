# Import the module files
Import-Module -Name "$PSScriptRoot\UserManagement.psm1" -Force
Import-Module -Name "$PSScriptRoot\DomainUtils.psm1" -Force
Import-Module -Name "$PSScriptRoot\Logging.psm1" -Force

# Create alias only if it doesn't exist
if (-not (Get-Alias -Name Find-ADUser -ErrorAction SilentlyContinue)) {
    Set-Alias -Name Find-ADUser -Value Search-ADUser -Scope Script
}

# Export all functions and aliases in a single statement
Export-ModuleMember -Function * -Alias *
