# CredentialManagement.psm1

function Get-DomainCredentials {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet("lux", "ess", "el")]
        [string]$Domain
    )
    
    try {
        # Initialize credential store
        $credentialPath = $global:adConfig.CredentialPath
        if (-not (Test-Path -Path $credentialPath)) {
            New-Item -Path $credentialPath -ItemType Directory -Force | Out-Null
        }
        
        $credentialFile = Join-Path -Path $credentialPath -ChildPath "$Domain.cred"
        
        # If credential file exists and is not expired, use it
        if (Test-Path $credentialFile) {
            $fileInfo = Get-Item $credentialFile
            $credentialAge = (Get-Date) - $fileInfo.LastWriteTime
            
            # Check if credentials are less than 30 days old
            if ($credentialAge.Days -lt 30) {
                $cred = Import-Clixml -Path $credentialFile
                Write-Host "Retrieved stored credentials for domain: $Domain"
                return $cred
            }
        }
        
        # If no valid credential file exists, prompt for credentials
        $domainInfo = $global:adConfig.GetDomainByAlias($Domain)
        if (-not $domainInfo) {
            throw "Invalid domain alias: $Domain"
        }
        
        $fullDomainName = $global:adConfig.GetFullDomainName($Domain)
        
        Write-Host "Please enter credentials for domain: $fullDomainName" -ForegroundColor Yellow
        $cred = Get-Credential -Message "Enter credentials for $fullDomainName domain"
        
        if (-not $cred) {
            throw "No credentials provided"
        }
        
        # Export credentials securely
        $cred | Export-Clixml -Path $credentialFile
        Write-Host "Stored new credentials for domain: $Domain"
        
        return $cred
    }
    catch {
        Write-Error "Failed to get credentials for $Domain domain: $($_.Exception.Message)"
        throw
    }
}

function Remove-DomainCredentials {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet("lux", "ess", "el")]
        [string]$Domain
    )
    
    try {
        $credentialPath = Initialize-CredentialStore -BasePath $PSScriptRoot
        $credentialFile = Join-Path -Path $credentialPath -ChildPath "$Domain.cred"
        
        if (Test-Path $credentialFile) {
            Remove-Item -Path $credentialFile -Force
            Write-PsLogInfo "Removed stored credentials for domain: $Domain"
        }
    }
    catch {
        Write-PsLogError "Failed to remove credentials for $Domain domain: $($_.Exception.Message)"
        throw
    }
}

# Export module members
Export-ModuleMember -Function Get-DomainCredentials, Remove-DomainCredentials