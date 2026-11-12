<#
.SYNOPSIS
  Makes a clean copy of the KeyMesh project that is safe to upload
  (GitHub web upload, OneDrive for the Mid-Point submission).

.DESCRIPTION
  Copies everything EXCEPT secrets, passwords and generated files,
  then checks the copy and refuses to continue if anything secret slipped in.

  Never copied:
    folders: .git .venv venv secrets .pytest_cache .vscode .idea
             __pycache__ *.egg-info build dist pgdata
    files:   .env *.pyc *.pem share_*.txt

.EXAMPLE
  # from the project root:
  powershell -ExecutionPolicy Bypass -File scripts\make_clean_copy.ps1

.EXAMPLE
  # also create a zip (for OneDrive / Mid-Point submission):
  powershell -ExecutionPolicy Bypass -File scripts\make_clean_copy.ps1 -Zip
#>
param(
    # Where the clean copy goes. Default: a folder NEXT TO the project.
    [string]$Destination = (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) "KeyMesh_upload"),
    [switch]$Zip
)

$ErrorActionPreference = "Stop"

# Project root = parent of the scripts folder
$Source = Split-Path $PSScriptRoot -Parent
$Source = (Resolve-Path $Source).Path
$Destination = [System.IO.Path]::GetFullPath($Destination)

Write-Host ""
Write-Host "KeyMesh clean copy" -ForegroundColor Cyan
Write-Host "  from: $Source"
Write-Host "  to:   $Destination"
Write-Host ""

# --- Safety: the destination must be outside the project -------------------
if ($Destination.TrimEnd('\').ToLower() -eq $Source.TrimEnd('\').ToLower() -or
    $Destination.ToLower().StartsWith($Source.TrimEnd('\').ToLower() + '\')) {
    Write-Host "ERROR: destination must be OUTSIDE the project folder." -ForegroundColor Red
    exit 1
}

# --- What we never copy ---------------------------------------------------
$ExcludeDirs  = @(".git", ".venv", "venv", "secrets", ".pytest_cache", ".vscode", ".idea",
                  "__pycache__", "*.egg-info", "build", "dist", "pgdata")
$ExcludeFiles = @(".env", "*.pyc", "*.pem", "share_*.txt")

# --- Copy (/MIR keeps the destination identical to the clean source) -------
# NOTE: /MIR deletes files in the destination that are not in the source.
# That is why the destination is a separate folder used only for this.
robocopy $Source $Destination /MIR /XD $ExcludeDirs /XF $ExcludeFiles /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) {
    Write-Host "ERROR: robocopy failed (exit code $LASTEXITCODE)." -ForegroundColor Red
    exit 1
}

# --- Check the copy: nothing secret may be inside --------------------------
$forbidden = Get-ChildItem -LiteralPath $Destination -Recurse -Force | Where-Object {
    $_.Name -in @(".env", "secrets", ".venv", "venv", ".pytest_cache", ".vscode", "__pycache__", ".git") -or
    $_.Name -like "*.egg-info" -or
    $_.Name -like "*.pem" -or
    $_.Name -like "share_*.txt"
}
if ($forbidden) {
    Write-Host "STOP: forbidden items found in the copy:" -ForegroundColor Red
    $forbidden | ForEach-Object { Write-Host "  $($_.FullName)" -ForegroundColor Red }
    Write-Host "Nothing was zipped. Do NOT upload this folder." -ForegroundColor Red
    exit 1
}

# --- Report: what was kept and what was left out (top level) ---------------
Write-Host "Kept (safe to upload):" -ForegroundColor Green
Get-ChildItem -LiteralPath $Destination -Force | Sort-Object Name | ForEach-Object {
    Write-Host "  [OK]   $($_.Name)" -ForegroundColor Green
}
Write-Host ""
Write-Host "Left out (stay on this computer only):" -ForegroundColor Yellow
$kept = (Get-ChildItem -LiteralPath $Destination -Force).Name
Get-ChildItem -LiteralPath $Source -Force | Where-Object { $_.Name -notin $kept } |
    Sort-Object Name | ForEach-Object { Write-Host "  [SKIP] $($_.Name)" -ForegroundColor Yellow }

# --- Warnings: files that SHOULD be there ----------------------------------
Write-Host ""
$expected = @(".gitignore", ".env.example", "README.md", "docker-compose.yml",
              ".github\workflows\ci.yml")
foreach ($item in $expected) {
    if (-not (Test-Path -LiteralPath (Join-Path $Destination $item))) {
        Write-Host "WARNING: missing $item" -ForegroundColor Yellow
    }
}

$files = Get-ChildItem -LiteralPath $Destination -Recurse -Force -File
$sizeMb = [math]::Round(($files | Measure-Object Length -Sum).Sum / 1MB, 2)
Write-Host ""
Write-Host "Clean copy ready: $($files.Count) files, $sizeMb MB" -ForegroundColor Cyan

# --- Optional zip ----------------------------------------------------------
if ($Zip) {
    $zipPath = "$Destination.zip"
    if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
    # -Force on Get-ChildItem so hidden items such as .github are included
    $items = (Get-ChildItem -LiteralPath $Destination -Force).FullName
    Compress-Archive -LiteralPath $items -DestinationPath $zipPath
    Write-Host "Zip created: $zipPath" -ForegroundColor Cyan
}
Write-Host ""
