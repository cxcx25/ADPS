<#
.SYNOPSIS
PowerShell module for domain management utilities
#>

function Get-DomainCredentials {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('lux', 'ess', 'el')]
        [string]$Domain
    )
    
    try {
        # Path to the single credential file
        $credFile = Join-Path -Path $PSScriptRoot -ChildPath "credentials.txt"
        if (-not (Test-Path $credFile)) {
            throw "Credentials file not found: $credFile"
        }

        # Read the credentials file
        $credentials = $null
        foreach ($line in Get-Content $credFile) {
            if ($line -match "^$($Domain)\s*:\s*user=([^;]+);\s*password=(.+)$") {
                $credentials = @{
                    'Username' = $matches[1].Trim()
                    'Password' = $matches[2].Trim()
                }
                break
            }
        }

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
        [string]$Domain
    )
    
    try {
        # Simple mapping of domain aliases to full domain names
        $domainMappings = @{
            'lux' = 'LUXGROUP.NET'
            'ess' = 'us.essilor.pvt'
            'el' = 'ELCORP.GROUP'
        }

        $fullDomain = $domainMappings[$Domain.ToLower()]
        if (-not $fullDomain) {
            throw "Invalid domain: $Domain"
        }

        # Get credentials for the domain
        $credentials = Get-DomainCredentials -Domain $Domain

        # Find a domain controller for the specified domain
        $dc = Get-ADDomainController -DomainName $fullDomain -Discover -NextClosestSite |
              Select-Object -First 1 -ExpandProperty HostName

        if (-not $dc) {
            throw "No domain controller found for domain: $fullDomain"
        }

        Write-PsLogInfo "Using domain controller: $dc"
        return $dc
    }
    catch {
        Write-PsLogError "Error in Get-DomainController: $($_.Exception.Message)"
        throw
    }
}

# Export all functions
Export-ModuleMember -Function Get-DomainCredentials, Get-DomainController


