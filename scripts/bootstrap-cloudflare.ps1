[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('staging', 'production')]
    [string]$Environment,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$AccountId,

    [ValidateSet('Prepare', 'Finalize')]
    [string]$Phase = 'Prepare',

    [ValidatePattern('^[A-Za-z0-9_.-]{1,100}$')]
    [string]$Profile,

    [string]$AccessTeamDomain,
    [string]$AccessAud,
    [string]$AdminEmails,
    [string]$AdminOrigin,
    [string]$GeneratorHostname,
    [string]$AdminHostname,
    [string]$ProjectRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true

function Invoke-Wrangler {
    param([Parameter(Mandatory = $true)][string[]]$Arguments, [switch]$Capture)
    $allArguments = @($Arguments)
    if (-not [string]::IsNullOrWhiteSpace($script:Profile)) {
        $allArguments += @('--profile', $script:Profile)
    }
    if ($Capture) {
        $output = & $script:NodePath $script:WranglerPath @allArguments 2>$null
        if ($LASTEXITCODE -ne 0) { throw "Wrangler read-only command failed (exit $LASTEXITCODE)." }
        return ($output -join [Environment]::NewLine)
    }
    & $script:NodePath $script:WranglerPath @allArguments
    if ($LASTEXITCODE -ne 0) { throw "Wrangler command failed (exit $LASTEXITCODE)." }
}

function Assert-CloudflareAccount {
    $whoami = Invoke-Wrangler -Arguments @('whoami') -Capture
    $ids = @([regex]::Matches($whoami, '(?i)(?<![a-f0-9])[a-f0-9]{32}(?![a-f0-9])') |
        ForEach-Object { $_.Value.ToLowerInvariant() } | Sort-Object -Unique)
    if ($ids -notcontains $script:AccountIdLower) {
        throw 'The authenticated Wrangler profile does not expose the expected Cloudflare Account ID.'
    }
    Write-Host "Cloudflare account ${script:AccountIdLower}: VERIFIED"
}

function Get-Names {
    if ($Environment -eq 'production') {
        return [ordered]@{
            Core = 'bitwarden-mxroute-core'
            Generator = 'bitwarden-mxroute-generator'
            Admin = 'bitwarden-mxroute-admin'
            Database = 'bitwarden-mxroute-production'
        }
    }
    return [ordered]@{
        Core = 'bitwarden-mxroute-core-staging'
        Generator = 'bitwarden-mxroute-generator-staging'
        Admin = 'bitwarden-mxroute-admin-staging'
        Database = 'bitwarden-mxroute-staging'
    }
}

function Get-DatabaseId {
    param([object]$Database)
    foreach ($propertyName in @('uuid', 'id')) {
        $property = $Database.PSObject.Properties[$propertyName]
        if ($null -ne $property -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
            return [string]$property.Value
        }
    }
    throw 'Cloudflare returned a D1 database without an ID.'
}

function Write-EnvironmentConfigs {
    param([string]$DatabaseId, [switch]$Final)
    $relativeRoot = '../../..'
    $core = [ordered]@{
        name = $script:Names.Core
        main = "$relativeRoot/workers/core/src/index.ts"
        compatibility_date = '2026-08-13'
        workers_dev = $false
        account_id = $script:AccountIdLower
        d1_databases = @([ordered]@{
            binding = 'DB'
            database_name = $script:Names.Database
            database_id = $DatabaseId
            migrations_dir = "$relativeRoot/workers/core/migrations"
        })
    }
    if ($Final) {
        $core.secrets = [ordered]@{ required = @('MXROUTE_SERVER', 'MXROUTE_USERNAME', 'MXROUTE_API_KEY', 'TOKEN_PEPPER', 'ENC_KEY_V1') }
        $core.triggers = [ordered]@{ crons = @('*/5 * * * *') }
    }

    $namespaceBase = if ($Environment -eq 'production') { 1000 } else { 1100 }
    $generator = [ordered]@{
        name = $script:Names.Generator
        main = "$relativeRoot/workers/generator/src/index.ts"
        compatibility_date = '2026-08-13'
        workers_dev = $false
        account_id = $script:AccountIdLower
        services = @([ordered]@{ binding = 'CORE'; service = $script:Names.Core; entrypoint = 'GeneratorEntrypoint' })
        ratelimits = @(
            [ordered]@{ name = 'PREAUTH_RATE_LIMITER'; namespace_id = [string]($namespaceBase + 1); simple = [ordered]@{ limit = 30; period = 60 } },
            [ordered]@{ name = 'TOKEN_RATE_LIMITER'; namespace_id = [string]($namespaceBase + 2); simple = [ordered]@{ limit = 5; period = 60 } }
        )
    }
    $admin = [ordered]@{
        name = $script:Names.Admin
        main = "$relativeRoot/workers/admin/src/index.ts"
        compatibility_date = '2026-08-13'
        workers_dev = $false
        account_id = $script:AccountIdLower
        services = @([ordered]@{ binding = 'CORE'; service = $script:Names.Core; entrypoint = 'AdminEntrypoint' })
        assets = [ordered]@{
            directory = "$relativeRoot/workers/admin/public"
            binding = 'ASSETS'
            run_worker_first = $true
        }
    }
    if ($Final) {
        $admin.vars = [ordered]@{
            ACCESS_TEAM_DOMAIN = $AccessTeamDomain
            ACCESS_AUD = $AccessAud
            ADMIN_EMAILS = $AdminEmails
            ADMIN_ORIGIN = $AdminOrigin
        }
    }

    [void][System.IO.Directory]::CreateDirectory($script:ConfigDirectory)
    [System.IO.File]::WriteAllText($script:CoreConfig, ($core | ConvertTo-Json -Depth 10))
    [System.IO.File]::WriteAllText($script:GeneratorConfig, ($generator | ConvertTo-Json -Depth 10))
    [System.IO.File]::WriteAllText($script:AdminConfig, ($admin | ConvertTo-Json -Depth 10))
}

function Assert-EnvironmentConfigs {
    param([switch]$AllowPlaceholder, [switch]$RequireFinal)
    $core = Get-Content -LiteralPath $script:CoreConfig -Raw | ConvertFrom-Json
    $generator = Get-Content -LiteralPath $script:GeneratorConfig -Raw | ConvertFrom-Json
    $admin = Get-Content -LiteralPath $script:AdminConfig -Raw | ConvertFrom-Json
    foreach ($entry in @(@($core, $script:Names.Core), @($generator, $script:Names.Generator), @($admin, $script:Names.Admin))) {
        if ($entry[0].name -ne $entry[1] -or $entry[0].account_id -ne $script:AccountIdLower -or $entry[0].workers_dev -ne $false) {
            throw 'Generated Worker name, account, or workers_dev setting is unsafe.'
        }
        if ($null -ne $entry[0].PSObject.Properties['routes']) { throw 'Generated configs must not contain public routes.' }
    }
    foreach ($publicWorker in @($generator, $admin)) {
        $binding = @($publicWorker.services | Where-Object { $_.binding -eq 'CORE' })
        if ($binding.Count -ne 1 -or $binding[0].service -ne $script:Names.Core) {
            throw 'Generator/Admin CORE service target does not match this environment.'
        }
        $serialized = $publicWorker | ConvertTo-Json -Depth 10
        if ($serialized -match 'DB|MXROUTE_SERVER|MXROUTE_USERNAME|MXROUTE_API_KEY|TOKEN_PEPPER|ENC_KEY_V1') {
            throw 'A public Worker config contains a Core-only binding.'
        }
    }
    if ($generator.services[0].entrypoint -ne 'GeneratorEntrypoint' -or $admin.services[0].entrypoint -ne 'AdminEntrypoint') {
        throw 'Core service bindings must select their least-privilege named entrypoint.'
    }
    $db = @($core.d1_databases | Where-Object { $_.binding -eq 'DB' })
    if ($db.Count -ne 1 -or $db[0].database_name -ne $script:Names.Database) { throw 'D1 binding name mismatch.' }
    $validDatabaseId = $db[0].database_id -match '^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$' -and $db[0].database_id -ne '00000000-0000-0000-0000-000000000000'
    if (-not $AllowPlaceholder -and -not $validDatabaseId) { throw 'D1 database ID is missing or still a placeholder.' }
    if ($RequireFinal) {
        foreach ($name in @('ACCESS_TEAM_DOMAIN', 'ACCESS_AUD', 'ADMIN_EMAILS', 'ADMIN_ORIGIN')) {
            if ([string]::IsNullOrWhiteSpace([string]$admin.vars.$name)) { throw "Admin variable $name is missing." }
        }
        if (@($core.triggers.crons) -notcontains '*/5 * * * *') { throw 'Core recovery cron is missing.' }
    }
    return [string]$db[0].database_id
}

function Assert-FinalInputs {
    if ($AccessTeamDomain -notmatch '^https://[a-z0-9.-]+\.cloudflareaccess\.com$') { throw 'AccessTeamDomain must be an HTTPS Cloudflare Access team domain.' }
    if ($AccessAud -notmatch '^[A-Za-z0-9_-]{8,256}$') { throw 'AccessAud is invalid.' }
    $emails = @($AdminEmails.Split(',') | ForEach-Object { $_.Trim() })
    if ($emails.Count -eq 0 -or @($emails | Where-Object { $_ -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$' }).Count -gt 0) { throw 'AdminEmails is invalid.' }
    if ($AdminOrigin -notmatch '^https://[a-z0-9.-]+$') { throw 'AdminOrigin must be an exact HTTPS origin without a path.' }
    foreach ($hostname in @($GeneratorHostname, $AdminHostname)) {
        $labels = @($hostname.Split('.'))
        if ($hostname.Length -gt 253 -or $labels.Count -lt 2 -or @($labels | Where-Object { $_ -notmatch '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$' }).Count -gt 0) {
            throw 'GeneratorHostname/AdminHostname must be lowercase DNS hostnames.'
        }
    }
    if ($AdminOrigin -ne "https://$AdminHostname") { throw 'AdminOrigin must exactly match AdminHostname.' }
}

if ($PSVersionTable.PSVersion.Major -lt 7) { throw 'PowerShell 7 or newer is required.' }
if ([string]::IsNullOrWhiteSpace($ProjectRoot)) { $ProjectRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath) }
$root = (Resolve-Path -LiteralPath $ProjectRoot).Path
foreach ($required in @('package.json', 'workers/core/src/index.ts', 'workers/core/migrations/0001.sql')) {
    if (-not (Test-Path -LiteralPath (Join-Path $root $required) -PathType Leaf)) { throw "Invalid ProjectRoot: missing $required" }
}
$script:NodePath = (Get-Command node -ErrorAction Stop).Source
if ([int]((& $script:NodePath -p "process.versions.node.split('.')[0]").Trim()) -lt 22) { throw 'Node.js 22 or newer is required.' }
$script:WranglerPath = Join-Path $root 'node_modules/wrangler/bin/wrangler.js'
if (-not (Test-Path -LiteralPath $script:WranglerPath -PathType Leaf)) { throw 'Run npm ci before bootstrap.' }
$script:Profile = $Profile
$script:AccountIdLower = $AccountId.ToLowerInvariant()
$script:Names = Get-Names
$script:ConfigDirectory = Join-Path $root ".wrangler/environments/$Environment"
$script:CoreConfig = Join-Path $script:ConfigDirectory 'core.jsonc'
$script:GeneratorConfig = Join-Path $script:ConfigDirectory 'generator.jsonc'
$script:AdminConfig = Join-Path $script:ConfigDirectory 'admin.jsonc'

$migrationFiles = @(Get-ChildItem -LiteralPath (Join-Path $root 'workers/core/migrations') -File -Filter '*.sql' | Sort-Object Name)
for ($index = 0; $index -lt $migrationFiles.Count; $index++) {
    if ($migrationFiles[$index].Name -ne ('{0:D4}.sql' -f ($index + 1))) { throw 'D1 migrations are not contiguous and ordered.' }
}
if ($migrationFiles.Count -eq 0) { throw 'No D1 migrations were found.' }

Push-Location $root
try {
    Assert-CloudflareAccount
    if ($Phase -eq 'Prepare') {
        Write-EnvironmentConfigs -DatabaseId '00000000-0000-0000-0000-000000000000'
        [void](Assert-EnvironmentConfigs -AllowPlaceholder)
        $databaseJson = Invoke-Wrangler -Arguments @('d1', 'list', '--json', '--config', $script:CoreConfig) -Capture
        $database = @($databaseJson | ConvertFrom-Json | Where-Object { $_.name -eq $script:Names.Database })
        if ($database.Count -gt 1) { throw 'Multiple D1 databases have the expected environment name.' }
        if ($database.Count -eq 0) {
            $target = "account=$script:AccountIdLower environment=$Environment config=$script:CoreConfig database=$($script:Names.Database)"
            if (-not $PSCmdlet.ShouldProcess($target, 'Create environment D1 and update generated Core config')) { return }
            Invoke-Wrangler -Arguments @('d1', 'create', $script:Names.Database, '--binding', 'DB', '--update-config', '--config', $script:CoreConfig)
        } else {
            $databaseId = Get-DatabaseId $database[0]
            Write-EnvironmentConfigs -DatabaseId $databaseId
        }
        $databaseId = Assert-EnvironmentConfigs
        $target = "account=$script:AccountIdLower environment=$Environment config=$script:CoreConfig database=$($script:Names.Database)/$databaseId core=$($script:Names.Core)"
        if ($PSCmdlet.ShouldProcess($target, 'Deploy private Core shell (workers_dev=false, no routes, no cron)')) {
            Invoke-Wrangler -Arguments @('deploy', '--config', $script:CoreConfig)
            Write-Host 'Private Core shell: DEPLOYED'
        }
        Write-Host "Generated configs: $script:ConfigDirectory"
        Write-Host 'Next: run set-secrets.ps1, configure Access, then run this script with -Phase Finalize.'
        return
    }

    Assert-FinalInputs
    if (-not (Test-Path -LiteralPath $script:CoreConfig)) { throw 'Run the Prepare phase first.' }
    $prepared = Get-Content -LiteralPath $script:CoreConfig -Raw | ConvertFrom-Json
    $preparedDb = @($prepared.d1_databases | Where-Object { $_.binding -eq 'DB' })
    if ($preparedDb.Count -ne 1) { throw 'Prepared D1 binding is missing.' }
    Write-EnvironmentConfigs -DatabaseId ([string]$preparedDb[0].database_id) -Final
    $databaseId = Assert-EnvironmentConfigs -RequireFinal
    $databaseJson = Invoke-Wrangler -Arguments @('d1', 'list', '--json', '--config', $script:CoreConfig) -Capture
    $database = @($databaseJson | ConvertFrom-Json | Where-Object { $_.name -eq $script:Names.Database })
    $remoteId = if ($database.Count -eq 1) { Get-DatabaseId $database[0] } else { '' }
    if ($remoteId -ne $databaseId) { throw 'Remote D1 identity does not match the generated environment config.' }
    $secretJson = Invoke-Wrangler -Arguments @('secret', 'list', '--name', $script:Names.Core, '--format', 'json', '--config', $script:CoreConfig) -Capture
    $secretNames = @($secretJson | ConvertFrom-Json | ForEach-Object { $_.name })
    foreach ($requiredSecret in @('MXROUTE_SERVER', 'MXROUTE_USERNAME', 'MXROUTE_API_KEY', 'TOKEN_PEPPER', 'ENC_KEY_V1')) {
        if ($secretNames -notcontains $requiredSecret) { throw "Core secret $requiredSecret is not set." }
    }
    $target = "account=$script:AccountIdLower environment=$Environment configs=$script:ConfigDirectory database=$($script:Names.Database)/$databaseId workers=$($script:Names.Core),$($script:Names.Generator),$($script:Names.Admin) domains=$GeneratorHostname,$AdminHostname"
    if ($PSCmdlet.ShouldProcess($target, 'Apply migrations, deploy Core, and publish Access-ready Generator/Admin domains')) {
        Invoke-Wrangler -Arguments @('d1', 'migrations', 'apply', 'DB', '--remote', '--config', $script:CoreConfig)
        Invoke-Wrangler -Arguments @('deploy', '--config', $script:CoreConfig)
        Invoke-Wrangler -Arguments @('deploy', '--config', $script:GeneratorConfig, '--domain', $GeneratorHostname)
        Invoke-Wrangler -Arguments @('deploy', '--config', $script:AdminConfig, '--domain', $AdminHostname)
        Invoke-Wrangler -Arguments @('types', '--config', $script:CoreConfig)
        Write-Host 'Migrations, final Workers/domains, and types: COMPLETE'
    }
} finally {
    Pop-Location
}
