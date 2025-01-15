class ADConfig {
    [string]$LogPath
    [hashtable]$Domains
    [string]$CredentialPath
    [hashtable]$RetrySettings
    [hashtable]$PasswordPolicy

    ADConfig() {
        $this.LogPath = Join-Path -Path $PSScriptRoot -ChildPath "ADManagement.log"
        $this.CredentialPath = Join-Path -Path $PSScriptRoot -ChildPath "Credentials"
        
        # Define domains with their configurations
        $this.Domains = @{
            "ELCORP.GROUP" = @{
                Alias = "el"
                DomainController = "elcorp.group"
                CredentialFile = Join-Path -Path $this.CredentialPath -ChildPath "el.cred"
            }
            "LUXGROUP.NET" = @{
                Alias = "lux"
                DomainController = "luxgroup.net"
                CredentialFile = Join-Path -Path $this.CredentialPath -ChildPath "lux.cred"
            }
            "us.essilor.pvt" = @{
                Alias = "ess"
                DomainController = "us.essilor.pvt"
                CredentialFile = Join-Path -Path $this.CredentialPath -ChildPath "ess.cred"
            }
        }

        # Retry settings for operations
        $this.RetrySettings = @{
            MaxAttempts = 3
            DelaySeconds = 5
        }

        # Password policy settings
        $this.PasswordPolicy = @{
            MinLength = 12
            RequireUppercase = $true
            RequireLowercase = $true
            RequireNumbers = $true
            RequireSpecialChars = $true
            SpecialChars = '!@#$%^&*(){}[]<>?/~.,'
        }

        # Create credential directory if it doesn't exist
        if (-not (Test-Path $this.CredentialPath)) {
            New-Item -Path $this.CredentialPath -ItemType Directory -Force | Out-Null
        }
    }

    # Method to get domain info by alias
    [hashtable] GetDomainByAlias([string]$alias) {
        return $this.Domains.Values | Where-Object { $_.Alias -eq $alias } | Select-Object -First 1
    }

    # Method to get full domain name by alias
    [string] GetFullDomainName([string]$alias) {
        return ($this.Domains.GetEnumerator() | 
                Where-Object { $_.Value.Alias -eq $alias } | 
                Select-Object -First 1).Key
    }
}

# Initialize the global config object
$global:adConfig = [ADConfig]::new()