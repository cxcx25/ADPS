

function Get-UserADInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$UserNames,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet("lux", "ess", "el")]
        [string]$Domain
    )
    
    try {
        # Get domain credentials
        $cred = Get-DomainCredentials -Domain $Domain
        $dc = Get-DomainController -Domain $Domain
        
        foreach ($username in $UserNames) {
            try {
                $user = Get-ADUser -Identity $username -Server $dc -Credential $cred -Properties *
                
                [PSCustomObject]@{
                    DisplayName               = $user.DisplayName
                    SamAccountName            = $user.SamAccountName
                    Name                      = $user.Name
                    PasswordExpired           = $user.PasswordExpired -eq $true
                    PasswordLastSet           = $user.PasswordLastSet
                    AccountExpirationDate     = if ($user.AccountExpirationDate) { $user.AccountExpirationDate } else { "No expiration date set" }
                    IsLocked                  = $user.LockedOut
                    IsDisabled                = -not $user.Enabled
                    UserPrincipalName         = $user.UserPrincipalName
                    WhenChanged               = $user.whenChanged
                    WhenCreated               = $user.whenCreated
                    Mail                      = $user.mail
                    Department                = $user.Department
                    DistinguishedName         = $user.DistinguishedName
                    PasswordExpirationDate    = if ($user.'msDS-UserPasswordExpiryTimeComputed' -and $user.'msDS-UserPasswordExpiryTimeComputed' -ne 0) { [datetime]::FromFileTime($user.'msDS-UserPasswordExpiryTimeComputed') } else { "Password does not expire." }
                }
                
                $userDetails | Format-List
                
                if ($user.LockedOut -or $user.PasswordExpired -or -not $user.Enabled) {
                    Write-Host "`nALERT ON:" -ForegroundColor Red
                    if ($user.LockedOut) { Write-Host "- Account is locked." -ForegroundColor Red }
                    if ($user.PasswordExpired) { Write-Host "- Password is expired." -ForegroundColor Red }
                    if (-not $user.Enabled) { Write-Host "- Account is disabled." -ForegroundColor Red }
                } else {
                    Write-Host "`nUser account is in good standing." -ForegroundColor Green
                }
            }
            catch {
                Write-Warning "Failed to get info for user $username : $($_.Exception.Message)"
                continue
            }
        }
    }
    catch {
        Write-Error "Error in Get-UserADInfo: $($_.Exception.Message)"
        throw
    }
}

function Unblock-UserAccount {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$Username,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet("lux", "ess", "el")]
        [string]$Domain
    )
    
    try {
        $cred = Get-DomainCredentials -Domain $Domain
        $dc = Get-DomainController -Domain $Domain
        
        foreach ($user in $Username) {
            try {
                Unlock-ADAccount -Identity $user -Server $dc -Credential $cred
                Write-Host "Successfully unlocked account for user: $user" -ForegroundColor Green
            }
            catch {
                Write-Warning "Failed to unlock account for user $user : $($_.Exception.Message)"
                continue
            }
        }
    }
    catch {
        Write-Error "Error in Unblock-UserAccount: $($_.Exception.Message)"
        throw
    }
}

function Reset-UserPassword {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$Username,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet("lux", "ess", "el")]
        [string]$Domain,
        
        [Parameter(Mandatory=$true)]
        [string]$NewPassword
    )
    
    try {
        $cred = Get-DomainCredentials -Domain $Domain
        $dc = Get-DomainController -Domain $Domain
        $securePassword = ConvertTo-SecureString -String $NewPassword -AsPlainText -Force
        
        foreach ($user in $Username) {
            try {
                Set-ADAccountPassword -Identity $user -Server $dc -Credential $cred -NewPassword $securePassword -Reset
                Set-ADUser -Identity $user -Server $dc -Credential $cred -ChangePasswordAtLogon $true
                Write-Host "Successfully reset password for user: $user" -ForegroundColor Green
            }
            catch {
                Write-Warning "Failed to reset password for user $user : $($_.Exception.Message)"
                continue
            }
        }
    }
    catch {
        Write-Error "Error in Reset-UserPassword: $($_.Exception.Message)"
        throw
    }
}

function Update-AccountExpiration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$Username,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet("lux", "ess", "el")]
        [string]$Domain,
        
        [Parameter(Mandatory=$true)]
        [int]$DaysToExtend
    )
    
    try {
        $cred = Get-DomainCredentials -Domain $Domain
        $dc = Get-DomainController -Domain $Domain
        
        foreach ($user in $Username) {
            try {
                $currentUser = Get-ADUser -Identity $user -Server $dc -Credential $cred -Properties AccountExpirationDate
                $newExpirationDate = if ($currentUser.AccountExpirationDate) {
                    $currentUser.AccountExpirationDate.AddDays($DaysToExtend)
                } else {
                    (Get-Date).AddDays($DaysToExtend)
                }
                
                Set-ADAccountExpiration -Identity $user -Server $dc -Credential $cred -DateTime $newExpirationDate
                Write-Host "Successfully extended account expiration for user: $user to $($newExpirationDate.ToString('yyyy-MM-dd'))" -ForegroundColor Green
            }
            catch {
                Write-Warning "Failed to update account expiration for user $user : $($_.Exception.Message)"
                continue
            }
        }
    }
    catch {
        Write-Error "Error in Update-AccountExpiration: $($_.Exception.Message)"
        throw
    }
}

# Export all functions
Export-ModuleMember -Function Get-UserADInfo, Unblock-UserAccount, Reset-UserPassword, Update-AccountExpiration