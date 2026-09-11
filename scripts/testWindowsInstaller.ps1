param(
    [Parameter(Mandatory = $true)]
    [string]$InstallerPath,
    [Parameter(Mandatory = $true)]
    [string]$ExpectedExecutablePath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($env:CI -ne 'true' -or $env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows' -or
    $env:GITHUB_REPOSITORY -ne 'visionsofparadise/credact' -or
    $env:GITHUB_RUN_ID -notmatch '^\d+$' -or -not $env:RUNNER_TEMP) {
    throw 'Installer tests require the disposable GitHub-hosted Windows CI account.'
}

$projectDirectory = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$workspaceDirectory = [IO.Path]::GetFullPath($env:GITHUB_WORKSPACE)
if ($projectDirectory.TrimEnd('\') -ne $workspaceDirectory.TrimEnd('\') -or
    $env:USERPROFILE -eq 'C:\Users\mttcv') {
    throw 'Installer tests refuse a local checkout or personal account.'
}

$installer = (Resolve-Path -LiteralPath $InstallerPath).Path
$expectedExecutable = (Resolve-Path -LiteralPath $ExpectedExecutablePath).Path
$installDirectory = Join-Path $env:LOCALAPPDATA 'credact'
$installedExecutable = Join-Path $installDirectory 'credact.exe'
$uninstallKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\credact'
$usage = 'Usage: credact [--no-output-scan] SOURCE [...] -- COMMAND [ARG ...]'
$evidenceDirectory = Join-Path $projectDirectory '.scratch/installer'
$observations = [Collections.Generic.List[object]]::new()
$processes = [Collections.Generic.List[object]]::new()

$report = [ordered]@{
    sourceCommit = $env:GITHUB_SHA
    installer = $installer
    installerHash = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant()
    expectedExecutableHash = (Get-FileHash -LiteralPath $expectedExecutable -Algorithm SHA256).Hash.ToLowerInvariant()
    installDirectory = $installDirectory
    platform = [Environment]::OSVersion.VersionString
    method = 'Native silent install, PATH resolution from a fresh shell, and silent uninstall in a disposable CI account'
    observations = $observations
    processes = $processes
}

function Assert-Condition([bool]$Condition, [string]$Name) {
    $observations.Add(@{ name = $Name; passed = $Condition })
    if (-not $Condition) { throw $Name }
}

function Get-RawUserPathEntries {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $false)
    try {
        $value = [string]$key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    } finally {
        $key.Close()
    }
    return @($value -split ';' | Where-Object { $_ })
}

function Invoke-Installer([string]$Path, [string[]]$Arguments) {
    $process = Start-Process -FilePath $Path -ArgumentList $Arguments -PassThru -WindowStyle Hidden
    if (-not $process.WaitForExit(180000)) {
        throw "Installer process $($process.Id) exceeded the three-minute limit."
    }
    $process.Refresh()
    $processes.Add(@{ executable = $Path; arguments = $Arguments; exitCode = $process.ExitCode })
    Assert-Condition ($process.ExitCode -eq 0) "Installer succeeded: $([IO.Path]::GetFileName($Path))"
}

[void](New-Item -ItemType Directory -Path $evidenceDirectory -Force)

try {
    Assert-Condition (-not (Test-Path -LiteralPath $uninstallKey)) 'Account carries no existing credact registration'

    Invoke-Installer $installer @('/S')

    Assert-Condition (Test-Path -LiteralPath $uninstallKey) 'Silent install creates the uninstall entry'

    $installedHash = (Get-FileHash -LiteralPath $installedExecutable -Algorithm SHA256).Hash.ToLowerInvariant()
    $report.installedExecutableHash = $installedHash
    Assert-Condition ($installedHash -eq $report.expectedExecutableHash) 'Installed executable matches the built binary'

    $report.userPathAfterInstall = Get-RawUserPathEntries
    Assert-Condition ((Get-RawUserPathEntries) -contains $installDirectory) 'Install adds the install directory to the raw user PATH'

    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $rebuiltPath = (@($machinePath, $userPath) | Where-Object { $_ }) -join ';'
    $previousPath = $env:Path
    try {
        $env:Path = $rebuiltPath
        $helpOutput = (& pwsh -NoProfile -Command 'credact --help' 2>&1 | Out-String)
        $helpExitCode = $LASTEXITCODE
    } finally {
        $env:Path = $previousPath
    }
    $processes.Add(@{ executable = 'pwsh -NoProfile -Command "credact --help"'; exitCode = $helpExitCode })
    $report.helpOutput = $helpOutput
    Assert-Condition ($helpExitCode -eq 0) 'A fresh shell resolves credact from the user PATH and runs it'
    Assert-Condition ($helpOutput.StartsWith($usage)) 'The resolved credact prints the usage line first'

    $uninstallerCopy = Join-Path $env:RUNNER_TEMP 'credact-uninstall.exe'
    Copy-Item -LiteralPath (Join-Path $installDirectory 'uninstall.exe') -Destination $uninstallerCopy
    Invoke-Installer $uninstallerCopy @('/S', "_?=$installDirectory")

    $report.userPathAfterUninstall = Get-RawUserPathEntries
    Assert-Condition (-not (Test-Path -LiteralPath $uninstallKey)) 'Uninstall removes the uninstall entry'
    Assert-Condition (-not (Test-Path -LiteralPath $installedExecutable)) 'Uninstall removes the executable'
    Assert-Condition ((Get-RawUserPathEntries) -notcontains $installDirectory) 'Uninstall removes the install directory from the raw user PATH'

    $report.passed = $true
} catch {
    $report.passed = $false
    $report.error = $_.Exception.Message
    throw
} finally {
    $report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $evidenceDirectory 'report.json') -Encoding utf8
}
