param(
    [int]$MaxRecords = 1000,
    [int]$BatchSize = 16,
    [switch]$All
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$databasePath = Join-Path $projectRoot "output\vulnerability-master.sqlite"
$modelPath = Join-Path $projectRoot "models\Qwen3-Embedding-0.6B"

if (-not (Test-Path -LiteralPath $databasePath -PathType Leaf)) {
    throw "Main database not found: $databasePath"
}
if (-not (Test-Path -LiteralPath (Join-Path $modelPath "model.safetensors") -PathType Leaf)) {
    throw "Qwen3 model weights not found: $modelPath"
}
if ($BatchSize -lt 1) {
    throw "BatchSize must be positive"
}
if (-not $All -and $MaxRecords -lt 1) {
    throw "MaxRecords must be positive unless -All is supplied"
}

$arguments = @(
    "-m", "vulntools",
    "--db", $databasePath,
    "index",
    "--model-path", $modelPath,
    "--batch-size", $BatchSize
)
if (-not $All) {
    $arguments += @("--max-records", $MaxRecords)
}

Push-Location $projectRoot
try {
    & python @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Semantic indexing failed with exit code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}
