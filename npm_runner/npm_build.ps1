param(
    [Parameter(Mandatory=$true)]
    [string]$RepoPath
)

Set-Location -LiteralPath $RepoPath
npm run build