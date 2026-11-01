$ErrorActionPreference = "Stop"
$Python = Join-Path (Get-Location) ".venv\\Scripts\\python.exe"

if (-not $env:IDS_ALERT_KEY) {
    Write-Error "Set IDS_ALERT_KEY to a private random secret before running the signed demo."
    exit 2
}

& $Python -m ids calibrate sample_data/ardupilot_sample.tlog --out profile --frac 0.5
New-Item -ItemType Directory -Force -Path run | Out-Null
& $Python -m ids replay sample_data/ardupilot_sample.tlog --profile profile --log run/replay-alerts.jsonl
& $Python -m ids bench sample_data/ardupilot_sample.tlog --out run/bench --seed 7
