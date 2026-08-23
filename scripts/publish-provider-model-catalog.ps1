[CmdletBinding()]
param(
    [ValidateSet('Preview', 'Publish', 'Monitor', 'InstallSchedule', 'UninstallSchedule')]
    [string]$Mode = 'Preview',
    [string]$PagesRepositoryPath = '',
    [string]$SignerRepositoryPath = '',
    [string]$EvidenceRoot = '',
    [string]$ResultPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $PSScriptRoot 'ProviderModelCatalogPublisher.psm1'
Import-Module $modulePath -Force

if ([string]::IsNullOrWhiteSpace($PagesRepositoryPath)) {
    $PagesRepositoryPath = Split-Path $PSScriptRoot -Parent
}
if ([string]::IsNullOrWhiteSpace($SignerRepositoryPath)) {
    $projectsRoot = Split-Path ([IO.Path]::GetFullPath($PagesRepositoryPath)) -Parent
    $SignerRepositoryPath = Join-Path $projectsRoot 'TaskPilotSignal'
}
if ([string]::IsNullOrWhiteSpace($EvidenceRoot)) {
    $EvidenceRoot = Join-Path $SignerRepositoryPath 'BuildArtifacts\1.2.0.0\provider_catalog_automation'
}
if ([string]::IsNullOrWhiteSpace($ResultPath)) {
    $ResultPath = Join-Path $EvidenceRoot 'latest-result.json'
}

function Write-SafeResultFile {
    param([Parameter(Mandatory)]$Value)
    $json = $Value | ConvertTo-Json -Compress -Depth 12
    $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($json)
    Write-AtomicBytes -Path $ResultPath -Bytes $bytes
    [Console]::Out.WriteLine($json)
}

function Assert-LocalAutomationPaths {
    $pages = [IO.Path]::GetFullPath($PagesRepositoryPath).TrimEnd('\')
    $signer = [IO.Path]::GetFullPath($SignerRepositoryPath).TrimEnd('\')
    $evidence = [IO.Path]::GetFullPath($EvidenceRoot).TrimEnd('\')
    $result = [IO.Path]::GetFullPath($ResultPath)
    $expectedEvidenceRoot = [IO.Path]::GetFullPath(
        (Join-Path $signer 'BuildArtifacts\1.2.0.0')).TrimEnd('\')
    if ([IO.Path]::GetFileName($pages) -cne 'TaskPilotSignalPages' -or
        [IO.Path]::GetFileName($signer) -cne 'TaskPilotSignal' -or
        -not $evidence.StartsWith($expectedEvidenceRoot + '\', [StringComparison]::OrdinalIgnoreCase) -or
        -not $result.StartsWith($evidence + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw [ArgumentException]::new('INVALID_ARGUMENT_BLOCKED')
    }
}

function Install-CatalogPublisherTask {
    Assert-LocalAutomationPaths
    if (-not $IsWindows) { throw [PlatformNotSupportedException]::new('SCHEDULE_INSTALL_BLOCKED') }
    $entryPoint = [IO.Path]::GetFullPath($PSCommandPath)
    $pwsh = (Get-Command pwsh -CommandType Application -ErrorAction Stop).Source
    $arguments = '-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -File "{0}" -Mode Publish' -f $entryPoint
    $action = New-ScheduledTaskAction -Execute $pwsh -Argument $arguments `
        -WorkingDirectory ([IO.Path]::GetFullPath($PagesRepositoryPath))
    $daily = New-ScheduledTaskTrigger -Daily -At '06:35'
    $atLogon = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
    $atLogon.Delay = 'PT5M'
    $settings = New-ScheduledTaskSettingsSet `
        -StartWhenAvailable `
        -MultipleInstances IgnoreNew `
        -ExecutionTimeLimit ([timespan]::FromMinutes(15)) `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries
    $principal = New-ScheduledTaskPrincipal `
        -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) `
        -LogonType Interactive `
        -RunLevel Limited
    $task = New-ScheduledTask -Action $action -Trigger @($daily, $atLogon) `
        -Settings $settings -Principal $principal `
        -Description 'Safely discovers, signs, and publishes TaskPilotSignal provider model catalog updates.'
    Register-ScheduledTask -TaskName 'TaskPilotSignal.ProviderModelCatalog' `
        -InputObject $task -Force | Out-Null
    return [pscustomobject]@{
        Status = 'pass'
        Operation = 'install-schedule'
        TaskName = 'TaskPilotSignal.ProviderModelCatalog'
        DailyLocalTime = '06:35'
        AtLogonDelayMinutes = 5
    }
}

function Uninstall-CatalogPublisherTask {
    if (-not $IsWindows) { throw [PlatformNotSupportedException]::new('SCHEDULE_INSTALL_BLOCKED') }
    $task = Get-ScheduledTask -TaskName 'TaskPilotSignal.ProviderModelCatalog' -ErrorAction SilentlyContinue
    if ($null -ne $task) {
        Unregister-ScheduledTask -TaskName 'TaskPilotSignal.ProviderModelCatalog' -Confirm:$false
    }
    return [pscustomobject]@{
        Status = 'pass'
        Operation = 'uninstall-schedule'
        TaskName = 'TaskPilotSignal.ProviderModelCatalog'
    }
}

try {
    $now = [datetimeoffset]::UtcNow
    $result = switch ($Mode) {
        'Preview' {
            Assert-LocalAutomationPaths
            Invoke-ProviderModelCatalogPreview `
                -PagesRepositoryPath $PagesRepositoryPath `
                -SignerRepositoryPath $SignerRepositoryPath `
                -EvidenceRoot $EvidenceRoot `
                -Now $now
        }
        'Publish' {
            Assert-LocalAutomationPaths
            Invoke-ProviderModelCatalogPreview `
                -PagesRepositoryPath $PagesRepositoryPath `
                -SignerRepositoryPath $SignerRepositoryPath `
                -EvidenceRoot $EvidenceRoot `
                -Now $now `
                -Publish
        }
        'Monitor' { Test-PublicProviderModelCatalog -Now $now }
        'InstallSchedule' { Install-CatalogPublisherTask }
        'UninstallSchedule' { Uninstall-CatalogPublisherTask }
    }
    $safe = [ordered]@{
        status = [string]$result.Status
        operation = [string]$result.Operation
        checkedAt = $now.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    foreach ($name in @(
            'ChangeRequired', 'Sequence', 'ExpiresAt', 'EnvelopeSha256',
            'NewModels', 'TaskName', 'DailyLocalTime', 'AtLogonDelayMinutes')) {
        if ($null -ne $result.PSObject.Properties[$name]) {
            $value = $result.$name
            if ($value -is [datetimeoffset]) {
                $value = $value.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
            }
            $safe[$name.Substring(0, 1).ToLowerInvariant() + $name.Substring(1)] = $value
        }
    }
    Write-SafeResultFile $safe
    exit 0
}
catch {
    $blocker = Get-CatalogPublisherBlocker $_.Exception
    if ($blocker -ceq 'INVALID_ARGUMENT_BLOCKED' -and
        $_.Exception.Message -in @('SCHEDULE_INSTALL_BLOCKED', 'INVALID_ARGUMENT_BLOCKED')) {
        $blocker = $_.Exception.Message
    }
    $safe = [ordered]@{
        status = 'blocked'
        operation = $Mode.ToLowerInvariant()
        checkedAt = [datetimeoffset]::UtcNow.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
        FailureSignature = $blocker
        Environment = if ($Mode -ceq 'Monitor') { 'github-monitor' } else { 'host-scheduled' }
    }
    try { Write-SafeResultFile $safe }
    catch { [Console]::Out.WriteLine(($safe | ConvertTo-Json -Compress -Depth 5)) }
    exit 1
}
