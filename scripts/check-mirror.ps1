<#
.SYNOPSIS
Checks the state of mirrored branches in various repos

.PARAMETER GitHubPat
PAT used to access GitHub repos.  If UseKeyVault is passed, may be omitted

.PARAMETER AzDOPat
PAT used to access AzDO repos.  If UseKeyVault is passed, may be omitted

.PARAMETER UseKeyVault
If passed, looks up secrets in keyvault

#>

param (
    [string]$GitHubPat,
    [string]$AzDOPat,
    [switch]$UseKeyVault,
    [string]$MirrorFile
)

function FetchBranches($cloneCache, $sourceRepo)

function CheckMirrorSource($sourceRepo, $targetRepo, $sourceBranch, $targetBranch, $cloneCache) {

}

function CheckMergeSource($sourceRepo, $targetRepo, $sourceBranch, $targetBranch, $cloneCache) {

}

$mirrorCheckMethods = @{
    "mirrorSource" = CheckMirrorSource;
    "mergeSource" = CheckMergeSource;
}

# If UseKeyVault is set, grab keys from keyvault
if ($UseKeyVault) {
    try {
        Write-Output "Obtaining required secrets from keyvault"
        $GitHubPat = $(Get-AzKeyVaultSecret -VaultName 'EngKeyVault' -Name 'dotnet-bot-user-repo-adminrepohook-pat' -ErrorAction Stop).SecretValueText
        $AzDOPat = $(Get-AzKeyVaultSecret -VaultName 'EngKeyVault' -Name 'dn-bot-dnceng-all-scopes' -ErrorAction Stop).SecretValueText
    }
    catch {
        Write-Error $_.Exception.Message
        Write-Error "Failed to gather required credentials from EngKeyVault.  Consider passing them in directly."
        exit
    }
} else {
    if (!$AzDOPat -or !$GitHubPat) {
        Write-Error "If not using key vault to find secrets, please provide VSTSPat, GitHubPat and MaestroSecret"
        exit
    }
}

$githubTokenSuffix = "?access_token=$GitHubPat"
$base64authinfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$AzDOPat"))
$azdoAuthHeader = @{"Authorization"="Basic $base64authinfo"}