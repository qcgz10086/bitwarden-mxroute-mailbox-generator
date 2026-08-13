[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('staging', 'production')]
    [string]$Environment,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$AccountId,

    [ValidatePattern('^[A-Za-z0-9_.-]{1,100}$')]
    [string]$Profile,

    [switch]$RotateMxroute,
    [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-WranglerRead {
    param([string[]]$Arguments)
    $allArguments = @($Arguments)
    if (-not [string]::IsNullOrWhiteSpace($script:Profile)) { $allArguments += @('--profile', $script:Profile) }
    $output = & $script:NodePath $script:WranglerPath @allArguments 2>$null
    if ($LASTEXITCODE -ne 0) { throw "Wrangler read-only command failed (exit $LASTEXITCODE)." }
    return ($output -join [Environment]::NewLine)
}

function Assert-CloudflareAccount {
    $whoami = Invoke-WranglerRead @('whoami')
    $ids = @([regex]::Matches($whoami, '(?i)(?<![a-f0-9])[a-f0-9]{32}(?![a-f0-9])') |
        ForEach-Object { $_.Value.ToLowerInvariant() } | Sort-Object -Unique)
    if ($ids -notcontains $script:AccountIdLower) {
        throw 'The authenticated Wrangler profile does not expose the expected Cloudflare Account ID.'
    }
}

function Assert-EnvironmentConfigs {
    $core = Get-Content -LiteralPath $script:CoreConfig -Raw | ConvertFrom-Json
    $generator = Get-Content -LiteralPath $script:GeneratorConfig -Raw | ConvertFrom-Json
    $admin = Get-Content -LiteralPath $script:AdminConfig -Raw | ConvertFrom-Json
    foreach ($entry in @(@($core, $script:CoreName), @($generator, $script:GeneratorName), @($admin, $script:AdminName))) {
        if ($entry[0].name -ne $entry[1] -or $entry[0].account_id -ne $script:AccountIdLower -or $entry[0].workers_dev -ne $false) {
            throw 'Generated Worker name, account, or workers_dev setting is unsafe.'
        }
        if ($null -ne $entry[0].PSObject.Properties['routes']) { throw 'Generated configs must not contain routes.' }
    }
    foreach ($publicWorker in @($generator, $admin)) {
        $binding = @($publicWorker.services | Where-Object { $_.binding -eq 'CORE' })
        if ($binding.Count -ne 1 -or $binding[0].service -ne $script:CoreName) { throw 'CORE service target mismatch.' }
    }
    $db = @($core.d1_databases | Where-Object { $_.binding -eq 'DB' })
    $validDatabaseId = $db.Count -eq 1 -and $db[0].database_id -match '^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$' -and $db[0].database_id -ne '00000000-0000-0000-0000-000000000000'
    if ($db.Count -ne 1 -or $db[0].database_name -ne $script:DatabaseName -or -not $validDatabaseId) {
        throw 'Prepared D1 binding does not match this environment.'
    }
    return [string]$db[0].database_id
}

function Get-DatabaseId {
    param([object]$Database)
    foreach ($propertyName in @('uuid', 'id')) {
        $property = $Database.PSObject.Properties[$propertyName]
        if ($null -ne $property -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)) { return [string]$property.Value }
    }
    throw 'Cloudflare returned a D1 database without an ID.'
}

function New-Base64UrlSecret {
    $bytes = [byte[]]::new(32)
    try {
        [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
        return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    } finally { [Array]::Clear($bytes, 0, $bytes.Length) }
}

function Invoke-SecretPut {
    param([string]$Name, [Security.SecureString]$SecureValue, [string]$PlainValue)
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $script:NodePath
    $start.UseShellExecute = $false
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $arguments = @($script:WranglerPath, 'secret', 'put', $Name, '--name', $script:CoreName, '--config', $script:CoreConfig)
    if (-not [string]::IsNullOrWhiteSpace($script:Profile)) { $arguments += @('--profile', $script:Profile) }
    foreach ($argument in $arguments) { [void]$start.ArgumentList.Add($argument) }

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    [void]$process.Start()
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $bstr = [IntPtr]::Zero
    try {
        if ($null -ne $SecureValue) {
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureValue)
            $length = [Runtime.InteropServices.Marshal]::ReadInt32($bstr, -4) / 2
            for ($index = 0; $index -lt $length; $index++) {
                $process.StandardInput.Write([char][Runtime.InteropServices.Marshal]::ReadInt16($bstr, $index * 2))
            }
        } else { $process.StandardInput.Write($PlainValue) }
        $process.StandardInput.WriteLine()
        $process.StandardInput.Close()
        $process.WaitForExit()
        [void]$stdoutTask.GetAwaiter().GetResult()
        [void]$stderrTask.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) { throw "Secret update failed (exit $($process.ExitCode))." }
    } finally {
        if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        $process.Dispose()
    }
}

if ($PSVersionTable.PSVersion.Major -lt 7) { throw 'PowerShell 7 or newer is required.' }
$root = (Resolve-Path -LiteralPath $ProjectRoot).Path
if (-not (Test-Path -LiteralPath (Join-Path $root 'package.json'))) { throw 'Invalid ProjectRoot.' }
$script:AccountIdLower = $AccountId.ToLowerInvariant()
$script:Profile = $Profile
$script:CoreName = if ($Environment -eq 'production') { 'bitwarden-mxroute-core' } else { 'bitwarden-mxroute-core-staging' }
$script:GeneratorName = if ($Environment -eq 'production') { 'bitwarden-mxroute-generator' } else { 'bitwarden-mxroute-generator-staging' }
$script:AdminName = if ($Environment -eq 'production') { 'bitwarden-mxroute-admin' } else { 'bitwarden-mxroute-admin-staging' }
$script:DatabaseName = "bitwarden-mxroute-$Environment"
$configDirectory = Join-Path $root ".wrangler/environments/$Environment"
$script:CoreConfig = Join-Path $configDirectory 'core.jsonc'
$script:GeneratorConfig = Join-Path $configDirectory 'generator.jsonc'
$script:AdminConfig = Join-Path $configDirectory 'admin.jsonc'
foreach ($config in @($script:CoreConfig, $script:GeneratorConfig, $script:AdminConfig)) {
    if (-not (Test-Path -LiteralPath $config -PathType Leaf)) { throw 'Run bootstrap-cloudflare.ps1 -Phase Prepare first.' }
}
$script:NodePath = (Get-Command node -ErrorAction Stop).Source
if ([int]((& $script:NodePath -p "process.versions.node.split('.')[0]").Trim()) -lt 22) { throw 'Node.js 22 or newer is required.' }
$script:WranglerPath = Join-Path $root 'node_modules/wrangler/bin/wrangler.js'
if (-not (Test-Path -LiteralPath $script:WranglerPath)) { throw 'Run npm ci before setting secrets.' }

Push-Location $root
try {
    Assert-CloudflareAccount
    $configuredDatabaseId = Assert-EnvironmentConfigs
    $databaseText = Invoke-WranglerRead @('d1', 'list', '--json', '--config', $script:CoreConfig)
    $database = @($databaseText | ConvertFrom-Json | Where-Object { $_.name -eq $script:DatabaseName })
    if ($database.Count -ne 1 -or (Get-DatabaseId $database[0]) -ne $configuredDatabaseId) {
        throw 'Remote D1 identity does not match the generated environment config.'
    }
    $existingText = Invoke-WranglerRead @('secret', 'list', '--name', $script:CoreName, '--format', 'json', '--config', $script:CoreConfig)
    $existing = @($existingText | ConvertFrom-Json | ForEach-Object { $_.name })
    $operationTarget = "account=$script:AccountIdLower environment=$Environment config=$script:CoreConfig worker=$script:CoreName database=$script:DatabaseName"

    foreach ($name in @('MXROUTE_SERVER', 'MXROUTE_USERNAME', 'MXROUTE_API_KEY')) {
        if (-not $RotateMxroute -and $existing -contains $name) { Write-Host "${name}: PRESENT"; continue }
        if (-not $PSCmdlet.ShouldProcess("$operationTarget secret=$name", 'Set secret through Wrangler stdin')) { Write-Host "${name}: WOULD SET"; continue }
        $value = Read-Host "Enter $name" -AsSecureString
        try {
            if ($value.Length -eq 0) { throw "$name cannot be empty." }
            Invoke-SecretPut -Name $name -SecureValue $value
        } finally { $value.Dispose() }
        Write-Host "${name}: SET"
    }
    foreach ($name in @('TOKEN_PEPPER', 'ENC_KEY_V1')) {
        if ($existing -contains $name) { Write-Host "${name}: PRESENT"; continue }
        if (-not $PSCmdlet.ShouldProcess("$operationTarget secret=$name", 'Generate and set 256-bit secret through Wrangler stdin')) { Write-Host "${name}: WOULD SET"; continue }
        $generated = New-Base64UrlSecret
        try { Invoke-SecretPut -Name $name -PlainValue $generated } finally { $generated = $null }
        Write-Host "${name}: SET"
    }
} finally { Pop-Location }
