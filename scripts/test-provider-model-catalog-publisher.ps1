[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'ProviderModelCatalogPublisher.psm1') -Force

$script:Assertions = 0

function Assert-True {
    param(
        [Parameter(Mandatory)][bool]$Condition,
        [Parameter(Mandatory)][string]$Message)
    $script:Assertions++
    if (-not $Condition) { throw [InvalidOperationException]::new($Message) }
}

function Assert-Equal {
    param(
        [AllowNull()]$Expected,
        [AllowNull()]$Actual,
        [Parameter(Mandatory)][string]$Message)
    $script:Assertions++
    if (-not [object]::Equals($Expected, $Actual)) {
        throw [InvalidOperationException]::new("$Message (expected=$Expected actual=$Actual)")
    }
}

function New-TestModel {
    param(
        [Parameter(Mandatory)][string]$Id,
        [string[]]$Aliases = @(),
        [string[]]$Efforts = @(),
        [AllowNull()][string]$DefaultEffort = $null)
    return [ordered]@{
        id = $Id
        status = 'active'
        replacement = $null
        aliases = @($Aliases)
        supportedEfforts = @($Efforts)
        defaultEffort = $DefaultEffort
    }
}

function New-TestPayload {
    param([datetimeoffset]$Now = [datetimeoffset]::UtcNow)
    return [ordered]@{
        schemaVersion = 2
        catalogVersion = '1.2.0.0'
        sequence = 7
        issuedAt = $Now.AddMinutes(-1).UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
        expiresAt = $Now.AddDays(90).UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
        providers = @(
            [ordered]@{
                id = 'antigravity'
                models = @((New-TestModel 'Existing AGY' @('existing-agy')))
            },
            [ordered]@{
                id = 'claude'
                models = @(
                    (New-TestModel 'claude-opus-4-8' @('opus', 'claude-opus-4-7') @('low', 'medium', 'high', 'xhigh', 'max') 'medium'),
                    (New-TestModel 'claude-sonnet-5' @('sonnet') @('low', 'medium', 'high', 'xhigh', 'max') 'medium'),
                    (New-TestModel 'claude-haiku-4-5' @('haiku') @('low', 'medium', 'high', 'xhigh', 'max') 'medium')
                )
            },
            [ordered]@{
                id = 'codex'
                models = @((New-TestModel 'gpt-existing' @() @('low', 'medium') 'medium'))
            },
            [ordered]@{
                id = 'ollama'
                models = @((New-TestModel 'llama3.2'))
            }
        )
    }
}

function New-TestEnvelope {
    param(
        [Parameter(Mandatory)][Collections.IDictionary]$Payload,
        [Parameter(Mandatory)][Security.Cryptography.ECDsa]$Key)
    $payloadJson = $Payload | ConvertTo-Json -Compress -Depth 20
    $payloadBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($payloadJson)
    $spki = $Key.ExportSubjectPublicKeyInfo()
    $keyId = 'sha256:' + [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($spki)).ToLowerInvariant()
    $signature = $Key.SignData(
        $payloadBytes,
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)
    $envelope = [ordered]@{
        schemaVersion = 1
        keyId = $keyId
        payloadBase64 = [Convert]::ToBase64String($payloadBytes)
        signatureBase64 = [Convert]::ToBase64String($signature)
    }
    return [pscustomobject]@{
        Bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(
            ($envelope | ConvertTo-Json -Compress -Depth 5))
        SpkiBase64 = [Convert]::ToBase64String($spki)
    }
}

function Invoke-EnvelopeTests {
    $now = [datetimeoffset]::UtcNow
    $key = [Security.Cryptography.ECDsa]::Create(
        [Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    try {
        $envelope = New-TestEnvelope (New-TestPayload $now) $key
        $verified = Read-VerifiedProviderCatalogBytes `
            -EnvelopeBytes $envelope.Bytes `
            -PinnedSpkiBase64 $envelope.SpkiBase64 `
            -Now $now
        Assert-Equal 7L $verified.Sequence 'Valid signed sequence was not accepted.'
        Assert-Equal 4 @($verified.Payload['providers']).Count 'Provider cardinality changed.'

        $tampered = $envelope.Bytes.Clone()
        $tampered[$tampered.Length - 5] = $tampered[$tampered.Length - 5] -bxor 1
        $blocked = $null
        try {
            [void](Read-VerifiedProviderCatalogBytes `
                    -EnvelopeBytes $tampered `
                    -PinnedSpkiBase64 $envelope.SpkiBase64 `
                    -Now $now)
        }
        catch { $blocked = Get-CatalogPublisherBlocker $_.Exception }
        Assert-True ($blocked -in @('CATALOG_ENVELOPE_BLOCKED', 'CATALOG_SIGNATURE_BLOCKED')) `
            'Tampered envelope did not fail closed.'
    }
    finally { $key.Dispose() }
}

function Invoke-MergeTests {
    $payload = New-TestPayload
    $codex = @(
        [ordered]@{
            id = 'gpt-new'
            aliases = @()
            supportedEfforts = @('low', 'medium', 'high')
            defaultEffort = 'medium'
        },
        [ordered]@{
            id = 'gpt-existing'
            aliases = @()
            supportedEfforts = @('low', 'medium')
            defaultEffort = 'medium'
        }
    )
    $antigravity = @(
        [ordered]@{ id = 'New AGY'; cliId = 'new-agy' },
        [ordered]@{ id = 'Existing AGY'; cliId = 'existing-agy' }
    )
    $claude = @(
        [ordered]@{ id = 'claude-opus-5'; friendlyName = 'Claude Opus 5' },
        [ordered]@{ id = 'claude-opus-4-8'; friendlyName = 'Claude Opus 4.8' },
        [ordered]@{ id = 'claude-sonnet-5'; friendlyName = 'Claude Sonnet 5' },
        [ordered]@{ id = 'claude-haiku-4-5'; friendlyName = 'Claude Haiku 4.5' }
    )
    $merged = Merge-ProviderModelDiscoveries $payload $codex $antigravity $claude
    Assert-True $merged.Changed 'New models did not request a catalog update.'

    $codexModels = @(($merged.Payload['providers'] | Where-Object { $_['id'] -ceq 'codex' })['models'])
    Assert-Equal 'gpt-new' $codexModels[0]['id'] 'New Codex model was not prepended.'
    Assert-True (@($codexModels | ForEach-Object { $_['id'] }) -contains 'gpt-existing') 'Existing Codex model was deleted.'

    $agyModels = @(($merged.Payload['providers'] | Where-Object { $_['id'] -ceq 'antigravity' })['models'])
    Assert-Equal 'New AGY' $agyModels[0]['id'] 'New Antigravity model was not prepended.'
    Assert-True (@($agyModels[0]['aliases']) -contains 'new-agy') 'Antigravity CLI mapping was lost.'

    $claudeModels = @(($merged.Payload['providers'] | Where-Object { $_['id'] -ceq 'claude' })['models'])
    Assert-Equal 'claude-opus-5' $claudeModels[0]['id'] 'New Claude model was not prepended.'
    Assert-True (@($claudeModels[0]['aliases']) -contains 'opus') 'Latest-family Claude alias was not transferred.'
    $oldOpus = $claudeModels | Where-Object { $_['id'] -ceq 'claude-opus-4-8' }
    Assert-True (@($oldOpus['aliases']) -notcontains 'opus') 'Old Claude family alias remained ambiguous.'
    Assert-True (@($claudeModels | ForEach-Object { $_['id'] }) -contains 'claude-opus-4-8') 'Older active Claude model was deleted.'

    $unchanged = Merge-ProviderModelDiscoveries `
        (New-TestPayload) `
        @($codex | Where-Object { $_['id'] -ceq 'gpt-existing' }) `
        @($antigravity | Where-Object { $_['id'] -ceq 'Existing AGY' }) `
        @($claude | Where-Object { $_['id'] -cne 'claude-opus-5' })
    Assert-True (-not $unchanged.Changed) 'Unchanged discovery produced catalog churn.'
}

function Invoke-ClaudeSourceTests {
    $markdown = @'
# Models

## Current Models (recommended)

| Friendly Name | Alias (use this) | Full ID | Context | Max Output | Status |
|---|---|---|---|---|---|
| Claude Opus 5 | `claude-opus-5` | — | 1M | 128K | Active |
| Claude Sonnet 5 | `claude-sonnet-5` | — | 1M | 128K | Active |
| Claude Haiku 4.5 | `claude-haiku-4-5` | `claude-haiku-4-5-20251001` | 200K | 64K | Active |
| Claude Mythos 5 | `claude-mythos-5` | — | 1M | 128K | Active (restricted) |

### Model Descriptions
'@
    $models = ConvertFrom-ClaudeModelsMarkdown $markdown
    Assert-Equal 3 @($models).Count 'Restricted Claude model was not excluded.'
    Assert-True (@($models | ForEach-Object { $_['id'] }) -contains 'claude-opus-5') 'Active Claude model was not parsed.'

    $blocked = $null
    try { [void](ConvertFrom-ClaudeModelsMarkdown ($markdown.Replace('claude-opus-5', '--unsafe'))) }
    catch { $blocked = Get-CatalogPublisherBlocker $_.Exception }
    Assert-Equal 'CLAUDE_DISCOVERY_BLOCKED' $blocked 'Unsafe Claude source did not fail closed.'
}

function Invoke-AutomationBoundaryTests {
    $module = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'ProviderModelCatalogPublisher.psm1')
    $entryPoint = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'publish-provider-model-catalog.ps1')
    $workflow = Get-Content -Raw -LiteralPath (
        Join-Path (Split-Path $PSScriptRoot -Parent) '.github\workflows\provider-model-catalog-monitor.yml')

    Assert-True ($module.Contains("$" + "script:ClaudeModelsUrl = 'https://raw.githubusercontent.com/anthropics/skills/")) `
        'Claude discovery is not pinned to the official Anthropic repository host.'
    Assert-True ($module.Contains("Throw-PublisherBlocker 'GIT_WORKTREE_BLOCKED'")) `
        'Dirty-worktree failure boundary is missing.'
    Assert-True ($module.Contains("'provider-models.v2.signed.json'")) `
        'Publisher target is not the single signed catalog file.'
    Assert-True (([regex]::Matches($module, 'provider-models\.v2\.payload\.json')).Count -eq 1 -and
        $module.Contains("'?? provider-models.v2.payload.json'")) `
        'Preserved Pages payload file must only appear in the dirty-worktree allowance.'
    Assert-True ($entryPoint.Contains('BuildArtifacts\1.2.0.0\provider_catalog_automation')) `
        'Evidence is not constrained to the approved ignored build root.'
    Assert-True ($entryPoint.Contains("'TaskPilotSignal.ProviderModelCatalog'")) `
        'Scheduled task identity changed unexpectedly.'
    Assert-True ($workflow.Contains('actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683')) `
        'GitHub checkout action is not commit pinned.'
    Assert-True ($workflow.Contains('persist-credentials: false')) `
        'GitHub checkout credentials are persisted.'
    Assert-True ($workflow.Contains('issues: write')) `
        'Failure reporting permission is missing.'
    Assert-True (-not $workflow.Contains('SIGNING') -and -not $workflow.Contains('CertificateThumbprint')) `
        'Cloud monitor must not own Production signing.'
    Assert-True (-not $workflow.Contains('pull_request_target')) `
        'Secret-adjacent pull_request_target trigger is forbidden.'
}

Invoke-EnvelopeTests
Invoke-MergeTests
Invoke-ClaudeSourceTests
Invoke-AutomationBoundaryTests

[Console]::Out.WriteLine(([ordered]@{
            status = 'pass'
            operation = 'publisher-tests'
            assertions = $script:Assertions
        } | ConvertTo-Json -Compress))
