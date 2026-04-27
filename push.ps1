# =============================================
# B01lers CTF 2026 - one-shot setup & push script
# =============================================
# Truoc khi chay: tao repo trong tren GitHub:
#   https://github.com/new
#   Repository name: B01lers-CTF-2026
#   Visibility: Public
#   KHONG tick "Add a README", "Add .gitignore", "Choose a license"
#
# Sau do tu PowerShell:
#   cd E:\ctf\cur\b01lers-ctf-2026
#   .\push.ps1
# =============================================

$ErrorActionPreference = 'Stop'
$RepoUrl = 'git@github.com:TrangTuanAnh/B01lers-CTF-2026.git'
# Neu khong co SSH key, doi dong tren thanh:
# $RepoUrl = 'https://github.com/TrangTuanAnh/B01lers-CTF-2026.git'

Write-Host "[1/5] Cleaning broken .git folder (created by Linux sandbox)..."
if (Test-Path .git) { Remove-Item .git -Recurse -Force }

Write-Host "[2/5] git init..."
git init -b main | Out-Null

Write-Host "[3/5] Removing __pycache__ if any..."
Get-ChildItem -Recurse -Force -Directory -Filter '__pycache__' -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "[4/5] git add + commit..."
git add .
$msg = @"
Initial commit: B01lers CTF 2026 web writeups (egg + clankers-market)

- egg: forge cookie (NaN) + race condition + path traversal -> read /proc/1/cmdline
- clankers-market: .git/index v4 path compression + git-dumper post-checkout hook -> SUID read-flag

Team UIT-creampie - 11th place (Open division), 7825 pts
"@
git commit -m $msg | Out-Null

Write-Host "[5/5] Adding remote and pushing..."
git remote remove origin 2>$null
git remote add origin $RepoUrl
git push -u origin main

Write-Host ""
Write-Host "DONE. Repo URL: https://github.com/TrangTuanAnh/B01lers-CTF-2026" -ForegroundColor Green
