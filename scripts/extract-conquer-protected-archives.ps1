param(
    [string]$GameRoot = "C:\Users\skull\OneDrive\Documents\Conquer Online 3.0",
    [string]$OutputRoot = "C:\Users\skull\OneDrive\Documents\Reverser\reports\conquer-protected-archives"
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$srcPath = Join-Path $repoRoot "src"
$env:PYTHONPATH = $srcPath + [IO.Path]::PathSeparator + $env:PYTHONPATH

$targets = @(
    @{ Name = "script"; Path = Join-Path $GameRoot "script.dat"; Output = Join-Path $OutputRoot "script" },
    @{ Name = "pcscript"; Path = Join-Path $GameRoot "pcscript.dat"; Output = Join-Path $OutputRoot "pcscript" }
)

function ConvertTo-PlainText([Security.SecureString]$SecureString) {
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

$securePassword = Read-Host "Archive password" -AsSecureString
$env:REVERSER_ARCHIVE_PASSWORD = ConvertTo-PlainText $securePassword

try {
    foreach ($target in $targets) {
        New-Item -ItemType Directory -Force -Path $target.Output | Out-Null
        python -m reverser.cli.main archive-export $target.Path $target.Output --password-env REVERSER_ARCHIVE_PASSWORD --stdout-format pretty
    }
}
finally {
    Remove-Item Env:REVERSER_ARCHIVE_PASSWORD -ErrorAction SilentlyContinue
}
