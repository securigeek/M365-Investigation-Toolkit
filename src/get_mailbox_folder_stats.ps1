param(
    [Parameter(Mandatory = $true)]
    [string]$Tenant,

    [Parameter(Mandatory = $true)]
    [string[]]$Mailbox
)

$ErrorActionPreference = "Stop"

Import-Module ExchangeOnlineManagement

Connect-ExchangeOnline -Organization $Tenant -ShowBanner:$false

$normalizedMailboxes = @()
foreach ($entry in $Mailbox) {
    foreach ($value in ($entry -split ",")) {
        $trimmed = $value.Trim()
        if ($trimmed) {
            $normalizedMailboxes += $trimmed
        }
    }
}

$rows = @()
$scopes = @("DeletedItems", "JunkEmail", "RecoverableItems")

foreach ($identity in $normalizedMailboxes) {
    foreach ($scope in $scopes) {
        $rows += Get-EXOMailboxFolderStatistics -Identity $identity -FolderScope $scope |
            Select-Object @{Name = "Mailbox"; Expression = { $identity } },
                Name,
                FolderType,
                ItemsInFolder,
                FolderAndSubfolderSize
    }
}

$rows | ConvertTo-Json -Depth 8
