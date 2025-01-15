<#
.SYNOPSIS
PowerShell module for domain management utilities
#>

# Import required modules
if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
    throw "The Active Directory module is required. Please install RSAT tools or import the AD module."
}
Import-Module ActiveDirectory -ErrorAction Stop

function Get-DomainController {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('lux', 'ess', 'el')]
        [string]$Domain
    )
    
    try {
        # Get domain info using ADConfig helper method
        $domainInfo = $global:adConfig.GetDomainByAlias($Domain)
        
        if (-not $domainInfo) {
            throw "Invalid domain alias: $Domain"
        }

        $dc = $domainInfo.DomainController
        if (-not $dc) {
            # Fallback to discovery if no DC is configured
            $fullDomainName = $global:adConfig.GetFullDomainName($Domain)
            
            # If still no domain found, try discovery
            if ($fullDomainName) {
                $dc = Get-ADDomainController -DomainName $fullDomainName -Discover -NextClosestSite |
                      Select-Object -First 1 -ExpandProperty HostName
            }
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

function Test-DomainConnection {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('lux', 'ess', 'el')]
        [string]$Domain
    )
    
    try {
        $dc = Get-DomainController -Domain $Domain
        $maxAttempts = $global:adConfig.RetrySettings.MaxAttempts
        $delay = $global:adConfig.RetrySettings.DelaySeconds

        for ($i = 1; $i -le $maxAttempts; $i++) {
            if (Test-Connection -ComputerName $dc -Count 1 -Quiet) {
                Write-PsLogInfo "Successfully connected to domain controller: $dc"
                return $true
            }
            
            if ($i -lt $maxAttempts) {
                Write-PsLogWarning "Attempt $i failed. Retrying in $delay seconds..."
                Start-Sleep -Seconds $delay
            }
        }

        Write-PsLogError "Failed to connect to domain controller after $maxAttempts attempts"
        return $false
    }
    catch {
        Write-PsLogError "Error testing domain connection: $($_.Exception.Message)"
        return $false
    }
}

function Get-DomainInfo {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('lux', 'ess', 'el')]
        [string]$Domain
    )
    
    try {
        $domainInfo = $global:adConfig.GetDomainByAlias($Domain)
        $fullDomainName = $global:adConfig.GetFullDomainName($Domain)
        
        if (-not $domainInfo -or -not $fullDomainName) {
            throw "Domain information not found for alias: $Domain"
        }

        return [PSCustomObject]@{
            Alias = $Domain
            FullDomainName = $fullDomainName
            DomainController = $domainInfo.DomainController
            CredentialFile = $domainInfo.CredentialFile
            IsConnected = Test-DomainConnection -Domain $Domain
        }
    }
    catch {
        Write-PsLogError "Error getting domain information: $($_.Exception.Message)"
        throw
    }
}

# Export the module members
Export-ModuleMember -Function Get-DomainController, Test-DomainConnection, Get-DomainInfo