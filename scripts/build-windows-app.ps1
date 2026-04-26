$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RootDir = Split-Path -Parent $PSScriptRoot
$DistDir = Join-Path $RootDir "dist"
$BuildDir = Join-Path $RootDir "build\\pyinstaller-windows"
$SpecFile = Join-Path $RootDir "packaging\\windows\\Reverser.spec"
$ExePath = Join-Path $DistDir "Reverser.exe"

Set-Location $RootDir

python -m pip install -U pip
python -m pip install -e ".[gui,macos-app]"

if (Test-Path $BuildDir) {
    Remove-Item -Recurse -Force $BuildDir
}
if (Test-Path $ExePath) {
    Remove-Item -Force $ExePath
}

pyinstaller `
    --noconfirm `
    --clean `
    --distpath $DistDir `
    --workpath $BuildDir `
    $SpecFile

Write-Host "Built $ExePath"
