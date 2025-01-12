# Define the ADConfig class
class ADConfig {
    [string]$LogPath
    [hashtable]$Domains
    [string]$CredentialFile
    [hashtable]$RetrySettings
    [hashtable]$PasswordPolicy

    ADConfig() {
        $this.LogPath = Join-Path -Path $PSScriptRoot -ChildPath "ADManagement.log"
        $this.Domains = @{
            "ELCORP.GROUP" = @{
                Alias = "el"
                DomainController = "elcorp.group"
            }
            "LUXGROUP.NET" = @{
                Alias = "lux"
                DomainController = "luxgroup.net"
            }
            "us.essilor.pvt" = @{
                Alias = "ess"
                DomainController = "us.essilor.pvt"
            }
        }
        $this.CredentialFile = Join-Path -Path $PSScriptRoot -ChildPath "credentials.txt"
        $this.RetrySettings = @{
            MaxAttempts = 3
            DelaySeconds = 5
        }
        $this.PasswordPolicy = @{
            MinLength = 12
            RequireUppercase = $true
            RequireLowercase = $true
            RequireNumbers = $true
            RequireSpecialChars = $true
            SpecialChars = '!@#$%^&*(){}[]<>?/~.,'
        }
    }
}

# Initialize the global config object
$global:adConfig = [ADConfig]::new()
