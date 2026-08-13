[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('staging', 'production')]
    [string]$Environment,

    [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true

function Resolve-SafeProjectRoot {
    param([string]$Path)
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    foreach ($relative in @(
        'package.json',
        'workers/core/wrangler.jsonc',
        'workers/core/migrations/0001.sql'
    )) {
        $candidate = Join-Path $resolved $relative
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            throw "ProjectRoot is not this repository: missing $relative"
        }
    }
    return $resolved
}

function Invoke-Wrangler {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [switch]$Capture
    )
    if ($Capture) {
        $output = & $script:NodePath $script:WranglerPath @Arguments 2>$null
        if ($LASTEXITCODE -ne 0) { throw "Wrangler command failed (exit $LASTEXITCODE)." }
        return ($output -join [Environment]::NewLine)
    }
    & $script:NodePath $script:WranglerPath @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Wrangler command failed (exit $LASTEXITCODE)." }
}

$root = Resolve-SafeProjectRoot $ProjectRoot
$script:NodePath = (Get-Command node -ErrorAction Stop).Source
$nodeMajor = [int]((& $script:NodePath -p "process.versions.node.split('.')[0]").Trim())
if ($nodeMajor -lt 22) { throw 'Node.js 22 or newer is required.' }
$script:WranglerPath = Join-Path $root 'node_modules/wrangler/bin/wrangler.js'
if (-not (Test-Path -LiteralPath $script:WranglerPath -PathType Leaf)) {
    throw 'Wrangler is not installed. Run npm ci with Node.js 22 or newer first.'
}

$coreConfig = Join-Path $root 'workers/core/wrangler.jsonc'
$migrationFiles = @(Get-ChildItem -LiteralPath (Join-Path $root 'workers/core/migrations') -File -Filter '*.sql' |
    Sort-Object Name)
if ($migrationFiles.Count -eq 0) { throw 'No D1 migrations were found.' }
for ($index = 0; $index -lt $migrationFiles.Count; $index++) {
    $expected = '{0:D4}.sql' -f ($index + 1)
    if ($migrationFiles[$index].Name -ne $expected) {
        throw "Migrations must be contiguous and ordered; expected $expected."
    }
}

Push-Location $root
try {
    [void](Invoke-Wrangler -Arguments @('whoami') -Capture)
    Write-Host 'Cloudflare authentication: OK'

    $databaseName = "bitwarden-mxroute-$Environment"
    $databasesJson = Invoke-Wrangler -Arguments @('d1', 'list', '--json') -Capture
    $databases = @($databasesJson | ConvertFrom-Json)
    $matches = @($databases | Where-Object { $_.name -eq $databaseName })
    if ($matches.Count -gt 1) { throw "More than one D1 database is named $databaseName." }

    if ($matches.Count -eq 0) {
        if ($PSCmdlet.ShouldProcess($databaseName, 'Create D1 database and update Core config')) {
            Invoke-Wrangler -Arguments @(
                'd1', 'create', $databaseName,
                '--binding', 'DB', '--update-config',
                '--config', $coreConfig
            )
            Write-Host "D1 ${databaseName}: CREATED"
        } else {
            Write-Host "D1 ${databaseName}: WOULD CREATE"
            return
        }
    } else {
        $configText = Get-Content -LiteralPath $coreConfig -Raw
        $databaseId = [string]$matches[0].uuid
        if ([string]::IsNullOrWhiteSpace($databaseId)) { $databaseId = [string]$matches[0].id }
        if (-not $configText.Contains($databaseName) -or -not $configText.Contains($databaseId)) {
            throw "D1 exists, but Core config is not bound to it. Safely update database_name/database_id before retrying."
        }
        Write-Host "D1 ${databaseName}: EXISTS AND BOUND"
    }

    if ($PSCmdlet.ShouldProcess($databaseName, "Apply $($migrationFiles.Count) ordered remote migrations")) {
        Invoke-Wrangler -Arguments @(
            'd1', 'migrations', 'apply', 'DB', '--remote',
            '--config', $coreConfig
        )
        Write-Host "D1 migrations 0001..$($migrationFiles[-1].BaseName): APPLIED"
    }

    if ($PSCmdlet.ShouldProcess($root, 'Regenerate Worker binding declarations')) {
        Invoke-Wrangler -Arguments @(
            'types',
            '--config', (Join-Path $root 'workers/core/wrangler.jsonc'),
            '--config', (Join-Path $root 'workers/generator/wrangler.jsonc'),
            '--config', (Join-Path $root 'workers/admin/wrangler.jsonc')
        )
        Write-Host 'Worker binding types: GENERATED'
    }
} finally {
    Pop-Location
}
