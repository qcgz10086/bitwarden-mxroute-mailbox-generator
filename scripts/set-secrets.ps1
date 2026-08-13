[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('staging', 'production')]
    [string]$Environment,

    [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$CoreWorkerName,
    [switch]$RotateMxroute
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function New-Base64UrlSecret {
    $bytes = [byte[]]::new(32)
    try {
        [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
        return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    } finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
}

function Invoke-SecretPut {
    param(
        [string]$Name,
        [Security.SecureString]$SecureValue,
        [string]$PlainValue
    )
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $script:NodePath
    $start.UseShellExecute = $false
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in @(
        $script:WranglerPath, 'secret', 'put', $Name,
        '--name', $script:WorkerName,
        '--config', $script:CoreConfig
    )) { [void]$start.ArgumentList.Add($argument) }

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
        } else {
            $process.StandardInput.Write($PlainValue)
        }
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

$root = (Resolve-Path -LiteralPath $ProjectRoot).Path
$script:CoreConfig = Join-Path $root 'workers/core/wrangler.jsonc'
if (-not (Test-Path -LiteralPath $script:CoreConfig -PathType Leaf)) {
    throw 'ProjectRoot is not this repository.'
}
$configText = Get-Content -LiteralPath $script:CoreConfig -Raw
foreach ($requiredName in @('MXROUTE_SERVER', 'MXROUTE_USERNAME', 'MXROUTE_API_KEY', 'TOKEN_PEPPER', 'ENC_KEY_V1')) {
    if (-not $configText.Contains('"' + $requiredName + '"')) {
        throw "Core config does not declare required secret $requiredName."
    }
}
$script:NodePath = (Get-Command node -ErrorAction Stop).Source
$nodeMajor = [int]((& $script:NodePath -p "process.versions.node.split('.')[0]").Trim())
if ($nodeMajor -lt 22) { throw 'Node.js 22 or newer is required.' }
$script:WranglerPath = Join-Path $root 'node_modules/wrangler/bin/wrangler.js'
if (-not (Test-Path -LiteralPath $script:WranglerPath -PathType Leaf)) {
    throw 'Wrangler is not installed. Run npm ci first.'
}
if ([string]::IsNullOrWhiteSpace($CoreWorkerName)) {
    $script:WorkerName = if ($Environment -eq 'production') {
        'bitwarden-mxroute-core'
    } else {
        'bitwarden-mxroute-core-staging'
    }
} elseif ($CoreWorkerName -notmatch '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$') {
    throw 'CoreWorkerName is not a valid Worker name.'
} else {
    $script:WorkerName = $CoreWorkerName
}

Push-Location $root
try {
    $existingText = & $script:NodePath $script:WranglerPath secret list --name $script:WorkerName --format json --config $script:CoreConfig 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'Unable to list Worker secrets. Deploy the Core Worker shell or verify its name first.' }
    $existing = @($existingText | ConvertFrom-Json | ForEach-Object { $_.name })

    foreach ($name in @('MXROUTE_SERVER', 'MXROUTE_USERNAME', 'MXROUTE_API_KEY')) {
        if (-not $RotateMxroute -and $existing -contains $name) {
            Write-Host "${name}: PRESENT"
            continue
        }
        if (-not $PSCmdlet.ShouldProcess("$script:WorkerName/$name", 'Set secret from protected interactive input')) {
            Write-Host "${name}: WOULD SET"
            continue
        }
        $value = Read-Host "Enter $name" -AsSecureString
        try {
            if ($value.Length -eq 0) { throw "$name cannot be empty." }
            Invoke-SecretPut -Name $name -SecureValue $value
        } finally {
            $value.Dispose()
        }
        Write-Host "${name}: SET"
    }

    foreach ($name in @('TOKEN_PEPPER', 'ENC_KEY_V1')) {
        if ($existing -contains $name) {
            Write-Host "${name}: PRESENT"
            continue
        }
        if (-not $PSCmdlet.ShouldProcess("$script:WorkerName/$name", 'Generate and set 256-bit secret')) {
            Write-Host "${name}: WOULD SET"
            continue
        }
        $generated = New-Base64UrlSecret
        try { Invoke-SecretPut -Name $name -PlainValue $generated }
        finally { $generated = $null }
        Write-Host "${name}: SET"
    }
} finally {
    Pop-Location
}
