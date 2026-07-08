python --version *> $null
if ($LASTEXITCODE -ne 0)
{
    Write-Error "Failed to find a Python executable."
    exit 1
}

$vswherePath = "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswherePath))
{
    Write-Error "Failed to find vswhere.exe."
    exit 1
}

$vsInstallationPath = & $vswherePath -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsInstallationPath)
{
    Write-Error "Failed to find a Visual Studio instance with MSVC."
    exit 1
}

$vcvarsallPath = Join-Path $vsInstallationPath "VC\Auxiliary\Build\vcvarsall.bat"
cmd /c """$vcvarsallPath"" amd64 & set" | ForEach-Object {
    if ($_ -match "^([^=]*)=(.*)$")
    {
        Set-Item -Force -Path "env:\$( $matches[1] )" -Value "$( $matches[2] )"
    }
}

if (-not $env:VCToolsInstallDir)
{
    Write-Error "Failed to find the MSVC tools installation directory."
    exit 1
}

$clPath = Join-Path $env:VCToolsInstallDir "bin\Hostx64\x64\cl.exe"
if (-not (Test-Path $clPath))
{
    Write-Error "Failed to find cl.exe."
    exit 1
}

$env:HOSTCC = $clPath

$rootPath = Split-Path -Parent $PSScriptRoot
$makeGeneratedFilesPath = Join-Path $rootPath "framework\scripts\make_generated_files.py"
python "$makeGeneratedFilesPath"