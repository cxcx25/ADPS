# Script configuration
$script:Config = @{
    LogPath = Join-Path -Path $PSScriptRoot -ChildPath "ADManagement.log"
    Domains = @{
        "ELCORP.GROUP" = @{ Alias = "el" }
        "LUXGROUP.NET" = @{ Alias = "lux" }
        "us.essilor.pvt" = @{ Alias = "ess" }
    }
    CredentialFile = Join-Path -Path $PSScriptRoot -ChildPath "credentials.txt"
}
