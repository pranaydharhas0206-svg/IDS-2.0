$ErrorActionPreference = "Stop"

Write-Host "Creating Python virtual environment..."
py -3.11 -m venv .venv
$Python = Join-Path (Get-Location) ".venv\\Scripts\\python.exe"

Write-Host "Installing project and test dependencies..."
& $Python -m pip install --upgrade pip
& $Python -m pip install -e ".[web]" pytest

Write-Host "Compiling IDS modules..."
& $Python -m compileall -q ids tests

Write-Host "Running full test suite..."
& $Python -m pytest -q

Write-Host "Setup complete. In VS Code select .venv as the Python interpreter."
