python --version >nul 2>&1
if ($LASTEXITCODE -ne 0)
{
    Write-Error "Failed to find a Python executable."
    exit 1
}

$rootPath = (Get-Item "$PSScriptRoot").Parent.Parent.FullName

$generateConfigChecksPath = Join-Path $rootPath "scripts\generate_config_checks.py"
python "$generateConfigChecksPath" "$rootPath\programs\sencrypt\include"

$generateDriverWrappersPath = Join-Path $rootPath "scripts\generate_driver_wrappers.py"
python "$generateDriverWrappersPath" --template-dir "$rootPath\programs\sencrypt\driver\templates" --json-dir "$rootPath\programs\sencrypt\driver\jsons" "$rootPath\programs\sencrypt\driver"
Move-Item -Path "$rootPath\programs\sencrypt\driver\psa_crypto_driver_wrappers.h" -Destination "$rootPath\programs\sencrypt\include" -Force
Move-Item -Path "$rootPath\programs\sencrypt\driver\psa_crypto_driver_wrappers_no_static.c" -Destination "$rootPath\programs\sencrypt\src" -Force