# verify.ps1 - verification harness for the MCP-authoring toolchain
# Exit 0 = all checks pass, 1 = any check fails. One PASS/FAIL line per check.
$ErrorActionPreference = "Continue"
$script:Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:VenvScripts = Join-Path $Root ".mcp-env\Scripts"
$script:PipxBin = Join-Path $env:USERPROFILE ".local\bin"
$script:AllPass = $true

function Add-PathOnce([string]$dir) {
    if ($dir -and (Test-Path $dir) -and ($env:PATH -notlike "*$dir*")) {
        $env:PATH = "$env:PATH;$dir"
    }
}
Add-PathOnce $VenvScripts
Add-PathOnce $PipxBin

function Test-Cmd([string]$Name, [scriptblock]$Check) {
    try { & $Check } catch { }
    if ($global:LASTEXITCODE -ne 0) { $script:AllPass = $false; Write-Output ("FAIL | {0}" -f $Name) }
    else { Write-Output ("PASS | {0}" -f $Name) }
}

# 1. versions
Test-Cmd "version: python" { python --version }
Test-Cmd "version: uv"     { uv --version }
Test-Cmd "version: node"   { node --version }
Test-Cmd "version: npm"    { npm --version }
Test-Cmd "version: git"    { git --version }
Test-Cmd "version: mcp"    { & (Join-Path $VenvScripts "mcp.exe") version }
Test-Cmd "version: site2mcp" { & (Join-Path $PipxBin "site2mcp.exe") --help }
Test-Cmd "version: npx"    { npx --version }

# 2. mcp --help lists dev
$help = (& (Join-Path $VenvScripts "mcp.exe") --help) 2>&1 | Out-String
if ($help -match "\bdev\b" -and $help -match "\binstall\b") { Write-Output "PASS | mcp --help lists dev+install" }
else { $script:AllPass = $false; Write-Output "FAIL | mcp --help lists dev+install" }

# 3. fastmcp importable, print version
$py = Join-Path $VenvScripts "python.exe"
$ver = (& $py -c "import fastmcp; print(fastmcp.__version__ if hasattr(fastmcp,'__version__') else 'ok')") 2>&1
if ($LASTEXITCODE -eq 0) { Write-Output ("PASS | fastmcp import (version: {0})" -f ($ver | Select-Object -Last 1)) }
else { $script:AllPass = $false; Write-Output "FAIL | fastmcp import" }

# 4. site2mcp --help lists learn
$shelp = (& (Join-Path $PipxBin "site2mcp.exe") --help) 2>&1 | Out-String
if ($shelp -match "\blearn\b" -and $shelp -match "\bserve\b") { Write-Output "PASS | site2mcp --help lists learn+serve" }
else { $script:AllPass = $false; Write-Output "FAIL | site2mcp --help lists learn+serve" }

# 5. npx @playwright/mcp@latest --help exit 0
& npx @playwright/mcp@latest --help *> $null
if ($LASTEXITCODE -eq 0) { Write-Output "PASS | npx @playwright/mcp --help" }
else { $script:AllPass = $false; Write-Output "FAIL | npx @playwright/mcp --help" }

if ($script:AllPass) { Write-Output "RESULT: ALL PASS"; exit 0 }
else { Write-Output "RESULT: FAILURES PRESENT"; exit 1 }
