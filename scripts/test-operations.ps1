[CmdletBinding()]
param([string]$ProjectRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw 'PowerShell 7 or newer is required to run operations safety tests.'
}
if ([string]::IsNullOrWhiteSpace($ProjectRoot)) { $ProjectRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath) }

$root = (Resolve-Path -LiteralPath $ProjectRoot).Path
$bootstrapPath = Join-Path $root 'scripts/bootstrap-cloudflare.ps1'
$secretsPath = Join-Path $root 'scripts/set-secrets.ps1'
$bootstrap = Get-Content -LiteralPath $bootstrapPath -Raw
$secrets = Get-Content -LiteralPath $secretsPath -Raw
$gitignore = Get-Content -LiteralPath (Join-Path $root '.gitignore') -Raw
$readme = Get-Content -LiteralPath (Join-Path $root 'README.md') -Raw
$operations = Get-Content -LiteralPath (Join-Path $root 'docs/operations.md') -Raw

foreach ($path in @($bootstrapPath, $secretsPath, $PSCommandPath)) {
    $tokens = $null
    $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
    if ($errors.Count -ne 0) { throw "PowerShell parse failure: $path" }
}

foreach ($text in @($bootstrap, $secrets)) {
    foreach ($required in @('AccountId', 'Assert-CloudflareAccount', '--profile')) {
        if (-not $text.Contains($required)) { throw "Missing account-safety control: $required" }
    }
}
foreach ($required in @('.wrangler/environments', "ValidateSet('Prepare', 'Finalize')", 'Assert-EnvironmentConfigs', 'Deploy private Core shell')) {
    if (-not $bootstrap.Contains($required)) { throw "Missing bootstrap control: $required" }
}
foreach ($required in @("'secret', 'list'", 'RedirectStandardInput', 'RandomNumberGenerator', 'ShouldProcess')) {
    if (-not $secrets.Contains($required)) { throw "Missing secret control: $required" }
}
if (($bootstrap + $secrets) -match '(?i)--value|PtrToString|ConvertFrom-SecureString') {
    throw 'A forbidden secret transport pattern is present.'
}
foreach ($required in @('Cloudflare API.txt', 'MXroute Email Hosting API.txt')) {
    if (-not $gitignore.Contains($required)) { throw "Missing credential-file ignore: $required" }
}
foreach ($document in @($readme, $operations)) {
    $finalizeWhatIf = $document.IndexOf('-Phase Finalize')
    $finalConfigDryRun = $document.IndexOf('.wrangler/environments/', $finalizeWhatIf)
    $finalizeConfirm = $document.IndexOf('-Phase Finalize', $finalizeWhatIf + 1)
    if ($finalizeWhatIf -lt 0 -or $finalConfigDryRun -lt $finalizeWhatIf -or $finalizeConfirm -lt $finalConfigDryRun) {
        throw 'Documentation must order Finalize -WhatIf, final generated-config dry-runs, then Finalize -Confirm.'
    }
}

# Execute only the config builder/validator functions from bootstrap. The main
# script (and therefore Wrangler) is never invoked by this regression test.
$bootstrapTokens = $null
$bootstrapErrors = $null
$bootstrapAst = [Management.Automation.Language.Parser]::ParseFile(
    $bootstrapPath, [ref]$bootstrapTokens, [ref]$bootstrapErrors
)
$functionNames = @('Get-Names', 'Write-EnvironmentConfigs', 'Assert-EnvironmentConfigs')
foreach ($functionAst in $bootstrapAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $functionNames -contains $node.Name
}, $true)) {
    . ([scriptblock]::Create($functionAst.Extent.Text))
}
foreach ($name in $functionNames) {
    if (-not (Get-Command $name -CommandType Function -ErrorAction SilentlyContinue)) { throw "Cannot load config function $name" }
}
$Environment = 'staging'
$script:AccountIdLower = '0123456789abcdef0123456789abcdef'
$script:Names = Get-Names
$script:ConfigDirectory = Join-Path $root '.wrangler/test-environments/staging'
$script:CoreConfig = Join-Path $script:ConfigDirectory 'core.jsonc'
$script:GeneratorConfig = Join-Path $script:ConfigDirectory 'generator.jsonc'
$script:AdminConfig = Join-Path $script:ConfigDirectory 'admin.jsonc'
$AccessTeamDomain = 'https://team.cloudflareaccess.com'
$AccessAud = 'static-test-audience'
$AdminEmails = 'admin@example.com'
$AdminOrigin = 'https://mail-admin.example.com'
$testDatabaseId = '11111111-1111-1111-1111-111111111111'
Write-EnvironmentConfigs -DatabaseId $testDatabaseId
$prepareCore = Get-Content -LiteralPath $script:CoreConfig -Raw | ConvertFrom-Json
if ($null -ne $prepareCore.PSObject.Properties['routes'] -or $null -ne $prepareCore.PSObject.Properties['triggers']) {
    throw 'Prepare Core shell gained a public route or cron.'
}
Write-EnvironmentConfigs -DatabaseId $testDatabaseId -Final
$validatedDatabaseId = Assert-EnvironmentConfigs -RequireFinal
if ($validatedDatabaseId -ne $testDatabaseId) { throw 'Generated config D1 identity regression.' }

Write-Host 'Operations static safety checks: PASS'
