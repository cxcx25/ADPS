
<#
.SYNOPSIS
PowerShell module for domain management utilities
#>

function Get-DomainCredentials {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('lux', 'ess', 'el')]
        [string]$Domain,
        
        [Parameter(Mandatory = $true)]
        [ADConfig]$AdConfig
    )
    
    try {
        $credFile = $AdConfig.CredentialFile
        if (-not (Test-Path $credFile)) {
            throw "Credentials file not found: $credFile"
        }

        $credentials = Get-Content $credFile | ForEach-Object {
            if ($_ -match "^$($Domain)\s*:\s*user=([^;]+);\s*password=(.+)$") {
                @{
                    'Username' = $matches[1].Trim()
                    'Password' = $matches[2].Trim()
                }
            }
        } | Select-Object -First 1

        if (-not $credentials) {
            throw "No credentials found for domain: $Domain"
        }

        $securePassword = ConvertTo-SecureString $credentials['Password'] -AsPlainText -Force
        return New-Object System.Management.Automation.PSCredential ($credentials['Username'], $securePassword)
    }
    catch {
        Write-PsLogError "Failed to get credentials for $Domain domain: $($_.Exception.Message)"
        throw
    }
}

function Get-DomainController {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('lux', 'ess', 'el')]
        [string]$Domain,

        [Parameter(Mandatory = $true)]
        [ADConfig]$AdConfig
    )
    
    try {
        $domainInfo = $AdConfig.Domains.Values | 
                     Where-Object { $_.Alias -eq $Domain } |
                     Select-Object -First 1

        if (-not $domainInfo) {
            throw "Invalid domain alias: $Domain"
        }

        $dc = $domainInfo.DomainController
        if (-not $dc) {
            # Fallback to discovery if no DC is configured
            $fullDomain = ($AdConfig.Domains.GetEnumerator() | 
                         Where-Object { $_.Value.Alias -eq $Domain }).Key
            
            $dc = Get-ADDomainController -DomainName $fullDomain -Discover -NextClosestSite |
                  Select-Object -First 1 -ExpandProperty HostName
        }

        if (-not $dc) {
            throw "No domain controller found for domain: $Domain"
        }

        Write-PsLogInfo "Using domain controller: $dc"
        return $dc
    }
    catch {
        Write-PsLogError "Error in Get-DomainController: $($_.Exception.Message)"
        throw
    }
}

Export-ModuleMember -Function Get-DomainCredentials, Get-DomainController
