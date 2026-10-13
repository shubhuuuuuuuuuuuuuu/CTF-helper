$ErrorActionPreference = 'Stop'
$ProjectRoot = $PSScriptRoot
$Python = Join-Path $ProjectRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $Python)) {
    py -3 -m venv (Join-Path $ProjectRoot '.venv')
    if ($LASTEXITCODE -ne 0) { throw 'Could not create the project virtual environment.' }
}
Push-Location $ProjectRoot
try {
    & $Python -m pip install -e '.[dev]'
    if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }
    & $Python -m PyInstaller --noconfirm --clean app.spec
    if ($LASTEXITCODE -ne 0) { throw 'PyInstaller build failed.' }
    Write-Host "Build output: $(Join-Path $ProjectRoot 'dist\CTF-Forge\CTF-Forge.exe')"
}
finally { Pop-Location }
