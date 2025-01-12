<#
.SYNOPSIS
PowerShell module for user management in Active Directory
#>

# Import the functions we depend on
. "$PSScriptRoot\Config.ps1"

function Get-UserADInfo {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Username,

        [Parameter(Mandatory=$true)]
        [ValidateSet("lux", "ess", "el")]
        [string]$Domain,

        [Parameter(Mandatory=$true)]
        [ADConfig]$AdConfig
    )

    try {
        $cred = Get-DomainCredentials -Domain $Domain -AdConfig $AdConfig
        $domainController = Get-DomainController -Domain $Domain -AdConfig $AdConfig

        Write-PsLogInfo "Connecting to $domainController..."

        $properties = 'PasswordExpired', 'PasswordLastSet', 'AccountExpirationDate',
                     'UserPrincipalName', 'whenChanged', 'whenCreated', 'mail',
                     'Department', 'DistinguishedName', 'DisplayName',
                     'msDS-UserPasswordExpiryTimeComputed', 'LockedOut', 'Enabled'

        $user = Get-ADUser -Identity $Username -Server $domainController -Credential $cred `
                          -Properties $properties -ErrorAction Stop
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        Write-PsLogError "User '$Username' not found in the '$Domain' domain."
        return
    }
    catch {
        Write-PsLogError "Error retrieving user information: $($_.Exception.Message)"
        throw
    }

        Write-PsLogInfo "Connected!"

        $userDetails = [PSCustomObject]@{
            DisplayName               = $user.DisplayName
            SamAccountName           = $user.SamAccountName
            Name                     = $user.Name
            PasswordExpired          = $user.PasswordExpired -eq $true
            PasswordLastSet          = $user.PasswordLastSet
            AccountExpirationDate    = if ($user.AccountExpirationDate) { $user.AccountExpirationDate } else { "No expiration date set" }
            IsLocked                 = $user.LockedOut
            IsDisabled               = -not $user.Enabled
            UserPrincipalName        = $user.UserPrincipalName
            WhenChanged              = $user.whenChanged
            WhenCreated              = $user.whenCreated
            Mail                     = $user.mail
            Department              = $user.Department
            DistinguishedName       = $user.DistinguishedName
            PasswordExpirationDate   = if ($user.'msDS-UserPasswordExpiryTimeComputed' -and $user.'msDS-UserPasswordExpiryTimeComputed' -ne 0) { [datetime]::FromFileTime($user.'msDS-UserPasswordExpiryTimeComputed') } else { "Password does not expire." }
        }

        $userDetails | Format-List

        if ($user.LockedOut -or $user.PasswordExpired -or -not $user.Enabled) {
            Write-PsLogWarning "ALERT ON:"
            if ($user.LockedOut) { Write-PsLogWarning "- Account is locked." }
            if ($user.PasswordExpired) { Write-PsLogWarning "- Password is expired." }
            if (-not $user.Enabled) { Write-PsLogWarning "- Account is disabled." }
        } else {
            Write-PsLogInfo "User account is in good standing."
        }
    }
    catch {
        Write-PsLogError "Error: $($_.Exception.Message)"
    }
}

function Unblock-UserAccount {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Username,

        [Parameter(Mandatory=$true)]
        [ValidateSet("lux", "ess", "el")]
        [string]$Domain
    )

    try {
        Write-PsLogInfo "Attempting to unblock account: $Username in domain: $Domain"

        $cred = Get-DomainCredentials -Domain $Domain
        $domainController = Get-DomainController -Domain $Domain

        # Get all domain controllers
        $dcs = Get-ADDomainController -Filter * -Server $domainController -Credential $cred |
               Select-Object -ExpandProperty HostName

        $successCount = 0
        $failCount = 0
        $failedDCs = @()
        $lockedDCs = @()
        $unlockedCount = 0

        foreach ($dc in $dcs) {
            try {
                # Check if account is locked on this DC
                $userStatus = Get-ADUser -Identity $Username -Server $dc -Properties LockedOut -Credential $cred

                if ($userStatus.LockedOut) {
                    $lockedDCs += $dc
                    Unlock-ADAccount -Identity $Username -Server $dc -Credential $cred

                    # Verify unlock
                    $verifyStatus = Get-ADUser -Identity $Username -Server $dc -Properties LockedOut -Credential $cred
                    if (-not $verifyStatus.LockedOut) {
                        $successCount++
                        Write-PsLogInfo "Successfully unlocked account on $dc"
                    }
                }
                else {
                    $unlockedCount++
                }
            }
            catch {
                $failCount++
                $failedDCs += $dc
                Write-PsLogError "Failed to contact DC: $dc - $($_.Exception.Message)"
            }
        }

        # Summary logging
        if ($lockedDCs.Count -gt 0) {
            Write-PsLogWarning "Account was locked on: $($lockedDCs -join ', ')"
        }
        if ($failedDCs.Count -gt 0) {
            Write-PsLogWarning "Failed to contact these DCs: $($failedDCs -join ', ')"
        }
        Write-PsLogInfo "Summary - Unlocked: $successCount, Already Unlocked: $unlockedCount, Failed: $failCount"
    }
    catch {
        Write-PsLogError "Error in unlock operation: $($_.Exception.Message)"
    }
}
<#
.SYNOPSIS
Resets a user's Active Directory password.
#>
function Reset-UserPassword {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Username,

        [Parameter(Mandatory = $true)]
        [ValidateSet("lux", "essilor", "el")]
        [string]$Domain,

        [Parameter(Mandatory = $true)]
        [string]$NewPassword,

        [Parameter(Mandatory = $true)]
        [ADConfig]$AdConfig
    )

    try {
        # Validate password complexity
        if ($NewPassword.Length -lt $AdConfig.PasswordPolicy.MinLength) { throw "Password must be at least $($AdConfig.PasswordPolicy.MinLength) characters" }
        if ($AdConfig.PasswordPolicy.RequireUppercase -and -not ($NewPassword -match '[A-Z]')) { throw "Password must contain uppercase letters" }
        if ($AdConfig.PasswordPolicy.RequireLowercase -and -not ($NewPassword -match '[a-z]')) { throw "Password must contain lowercase letters" }
        if ($AdConfig.PasswordPolicy.RequireNumbers -and -not ($NewPassword -match '[0-9]')) { throw "Password must contain numbers" }
        if ($AdConfig.PasswordPolicy.RequireSpecialChars -and -not ($NewPassword -match $AdConfig.PasswordPolicy.SpecialChars)) {
            Write-PsLogWarning "Password does not contain special characters"
        }

        Write-PsLogInfo "Attempting to reset password for user: $Username in domain: $Domain"

        $cred = Get-DomainCredentials -Domain $Domain -AdConfig $AdConfig
        $domainController = Get-DomainController -Domain $Domain -AdConfig $AdConfig

        # Verify user exists
        $user = Get-ADUser -Identity $Username -Server $domainController -Credential $cred

        # Increase the timeout limit and add error handling for password reset
        $timeoutLimit = $AdConfig.RetrySettings.MaxAttempts
        $retryCount = $AdConfig.RetrySettings.MaxAttempts
        $retryDelay = $AdConfig.RetrySettings.DelaySeconds

        for ($i = 0; $i -lt $retryCount; $i++) {
            try {
                # Reset password
                $securePassword = ConvertTo-SecureString $NewPassword -AsPlainText -Force
                Set-ADAccountPassword -Identity $Username -NewPassword $securePassword -Server $domainController -Credential $cred -ErrorAction Stop

                Write-PsLogInfo "Successfully reset password for $Username"
                break # Exit loop on success
            }
            catch {
                if ($i -eq $retryCount - 1) {
                    Write-PsLogError "Failed to reset password after $retryCount attempts: $($_.Exception.Message)"
                    throw
                }
                else {
                    Write-PsLogWarning "Attempt $($i + 1) failed. Retrying in $retryDelay seconds..."
                    Start-Sleep -Seconds $retryDelay
                }
            }
        }
    }
    catch {
        Write-PsLogError "Failed to reset password: $($_.Exception.Message)"
        throw
    }
}

<#
.SYNOPSIS
Extends the expiration date of a user's Active Directory account.
#>
function Update-AccountExpiration {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Username,

        [Parameter(Mandatory = $true)]
        [ValidateSet("lux", "essilor")]
        [string]$Domain,

        [Parameter(Mandatory = $true)]
        [int]$DaysToExtend,

        [Parameter(Mandatory = $true)]
        [ADConfig]$AdConfig
    )

    try {
        Write-PsLogInfo "Extending account expiration for user: $Username in domain: $Domain by $DaysToExtend days"

        $cred = Get-DomainCredentials -Domain $Domain -AdConfig $AdConfig
        $domainController = Get-DomainController -Domain $Domain -AdConfig $AdConfig

        # Get current expiration date
        $user = Get-ADUser -Identity $Username -Server $domainController -Credential $cred -Properties AccountExpirationDate

        # Calculate new expiration date
        $currentExpiration = if ($user.AccountExpirationDate) { $user.AccountExpirationDate } else { Get-Date }
        $newExpiration = $currentExpiration.AddDays($DaysToExtend)

        # Update expiration date
        Set-ADUser -Identity $Username -Server $domainController -Credential $cred -AccountExpirationDate $newExpiration

        Write-PsLogInfo "Successfully extended account expiration for $Username to $newExpiration"
        Write-Host "Account expiration date for $Username has been extended to $newExpiration" -ForegroundColor Green
    }
    catch {
        Write-PsLogError "Error extending account expiration: $($_.Exception.Message)"
        throw
    }
}

# Export all functions
Export-ModuleMember -Function Get-UserADInfo, Unblock-UserAccount, Reset-UserPassword, Update-AccountExpiration
