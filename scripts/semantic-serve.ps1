param(
    [int]$Port = 8765
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

Push-Location $projectRoot
try {
    & python -m vulntools --db $databasePath serve --model-path $modelPath --port $Port
    if ($LASTEXITCODE -ne 0) {
        throw "Semantic service failed with exit code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}
