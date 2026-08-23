Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:CatalogVersion = '1.2.0.0'
$script:CatalogUrl = 'https://taskpilotsignal.github.io/TaskPilotSignalPages/provider-models.v2.signed.json'
$script:ClaudeModelsUrl = 'https://raw.githubusercontent.com/anthropics/skills/main/skills/claude-api/shared/models.md'
$script:ProductionSpkiBase64 = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEU/kZNWQqGNvqCujjyH3CSa+G0HEvCiF8WAwJj9MVssoMHHosMkJS72e6hsE90DWqtxTW/93c0244mwh7ZKvV0A=='
$script:MaximumEnvelopeBytes = 262144
$script:MaximumPayloadBytes = 184320
$script:MaximumSourceBytes = 524288
$script:MaximumModelsPerProvider = 128
$script:AllowedEfforts = @('low', 'medium', 'high', 'xhigh', 'max', 'ultra')
$script:ExpectedProviderIds = @('antigravity', 'claude', 'codex', 'ollama')
$script:SafeLabelPattern = [regex]::new(
    '\A[\p{L}\p{N}][\p{L}\p{N} ._+:/()\-]{0,127}\z',
    [Text.RegularExpressions.RegexOptions]::CultureInvariant)
$script:SafeModelIdPattern = [regex]::new(
    '\A[a-zA-Z0-9][a-zA-Z0-9._+:/\-]{0,127}\z',
    [Text.RegularExpressions.RegexOptions]::CultureInvariant)
$script:AllowedBlockers = [Collections.Generic.HashSet[string]]::new(
    [string[]]@(
        'CATALOG_ENVELOPE_BLOCKED', 'CATALOG_EXPIRED_BLOCKED',
        'CATALOG_MONITOR_BLOCKED', 'CATALOG_PAYLOAD_BLOCKED',
        'CATALOG_ROLLBACK_BLOCKED', 'CATALOG_SIGNATURE_BLOCKED',
        'CERT_RENEWAL_REQUIRED', 'CLAUDE_DISCOVERY_BLOCKED',
        'CODEX_DISCOVERY_BLOCKED', 'DISCOVERY_RESULT_BLOCKED',
        'GIT_COMMIT_BLOCKED', 'GIT_DIVERGED_BLOCKED', 'GIT_PUSH_BLOCKED',
        'GIT_WORKTREE_BLOCKED', 'INVALID_ARGUMENT_BLOCKED',
        'MODEL_MERGE_BLOCKED', 'OUTPUT_WRITE_BLOCKED',
        'PUBLICATION_READBACK_BLOCKED', 'SCHEDULE_INSTALL_BLOCKED',
        'SIGNING_IDENTITY_BLOCKED', 'SIGNING_TOOL_BLOCKED',
        'SOURCE_DOWNLOAD_BLOCKED', 'SOURCE_SCHEMA_BLOCKED'),
    [StringComparer]::Ordinal)

class ProviderCatalogPublisherException : Exception {
    [string]$Code

    ProviderCatalogPublisherException([string]$code) : base($code) {
        $this.Code = $code
    }
}

function Throw-PublisherBlocker {
    param([Parameter(Mandatory)][string]$Code)
    $safeCode = if ($script:AllowedBlockers.Contains($Code)) { $Code } else { 'INVALID_ARGUMENT_BLOCKED' }
    throw [ProviderCatalogPublisherException]::new($safeCode)
}

function Get-CatalogPublisherBlocker {
    param([Exception]$Exception)
    if ($null -ne $Exception -and
        $Exception.GetType() -eq [ProviderCatalogPublisherException] -and
        $script:AllowedBlockers.Contains(([ProviderCatalogPublisherException]$Exception).Code)) {
        return ([ProviderCatalogPublisherException]$Exception).Code
    }
    return 'INVALID_ARGUMENT_BLOCKED'
}

function Get-Sha256Hex {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
}

function Get-ExpectedCatalogKeyId {
    $spki = [Convert]::FromBase64String($script:ProductionSpkiBase64)
    return 'sha256:' + (Get-Sha256Hex $spki)
}

function Test-SafeLabel {
    param([AllowEmptyString()][string]$Value)
    return -not [string]::IsNullOrWhiteSpace($Value) -and
        $Value.Length -le 128 -and
        [string]::Equals($Value, $Value.Trim(), [StringComparison]::Ordinal) -and
        -not $Value.StartsWith('-', [StringComparison]::Ordinal) -and
        -not $Value.ToCharArray().Where({ [char]::IsControl($_) }, 'First') -and
        $script:SafeLabelPattern.IsMatch($Value)
}

function Assert-NoDuplicateJsonProperties {
    param([Parameter(Mandatory)][Text.Json.JsonElement]$Element)
    if ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Object) {
        $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($property in $Element.EnumerateObject()) {
            if (-not $names.Add($property.Name)) { Throw-PublisherBlocker 'CATALOG_ENVELOPE_BLOCKED' }
            Assert-NoDuplicateJsonProperties $property.Value
        }
    }
    elseif ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Array) {
        foreach ($item in $Element.EnumerateArray()) { Assert-NoDuplicateJsonProperties $item }
    }
}

function Test-ExactJsonFields {
    param(
        [Parameter(Mandatory)][Text.Json.JsonElement]$Element,
        [Parameter(Mandatory)][string[]]$Fields)
    if ($Element.ValueKind -ne [Text.Json.JsonValueKind]::Object) { return $false }
    $actual = @($Element.EnumerateObject() | ForEach-Object Name)
    if ($actual.Count -ne $Fields.Count) { return $false }
    foreach ($field in $Fields) {
        if ($actual -cnotcontains $field) { return $false }
    }
    return $true
}

function ConvertFrom-StrictUtf8 {
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][string]$Blocker)
    try { return [Text.UTF8Encoding]::new($false, $true).GetString($Bytes) }
    catch { Throw-PublisherBlocker $Blocker }
}

function ConvertFrom-CanonicalBase64 {
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string]$Blocker)
    try { $bytes = [Convert]::FromBase64String($Value) }
    catch { Throw-PublisherBlocker $Blocker }
    if (-not [string]::Equals([Convert]::ToBase64String($bytes), $Value, [StringComparison]::Ordinal)) {
        Throw-PublisherBlocker $Blocker
    }
    return ,$bytes
}

function Read-VerifiedProviderCatalogBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$EnvelopeBytes,
        [string]$PinnedSpkiBase64 = $script:ProductionSpkiBase64,
        [datetimeoffset]$Now = [datetimeoffset]::UtcNow,
        [switch]$AllowExpired)

    if ($EnvelopeBytes.Length -le 0 -or $EnvelopeBytes.Length -gt $script:MaximumEnvelopeBytes) {
        Throw-PublisherBlocker 'CATALOG_ENVELOPE_BLOCKED'
    }
    $json = ConvertFrom-StrictUtf8 $EnvelopeBytes 'CATALOG_ENVELOPE_BLOCKED'
    try {
        $document = [Text.Json.JsonDocument]::Parse($json, [Text.Json.JsonDocumentOptions]@{
                AllowTrailingCommas = $false
                CommentHandling = [Text.Json.JsonCommentHandling]::Disallow
                MaxDepth = 16
            })
    }
    catch { Throw-PublisherBlocker 'CATALOG_ENVELOPE_BLOCKED' }
    try {
        $root = $document.RootElement
        Assert-NoDuplicateJsonProperties $root
        if (-not (Test-ExactJsonFields $root @('schemaVersion', 'keyId', 'payloadBase64', 'signatureBase64'))) {
            Throw-PublisherBlocker 'CATALOG_ENVELOPE_BLOCKED'
        }
        if ($root.GetProperty('schemaVersion').GetInt32() -ne 1) {
            Throw-PublisherBlocker 'CATALOG_ENVELOPE_BLOCKED'
        }
        $spki = ConvertFrom-CanonicalBase64 $PinnedSpkiBase64 'CATALOG_SIGNATURE_BLOCKED'
        $expectedKeyId = 'sha256:' + (Get-Sha256Hex $spki)
        $keyId = $root.GetProperty('keyId').GetString()
        if (-not [string]::Equals($keyId, $expectedKeyId, [StringComparison]::Ordinal)) {
            Throw-PublisherBlocker 'CATALOG_SIGNATURE_BLOCKED'
        }
        $payloadBytes = ConvertFrom-CanonicalBase64 `
            ($root.GetProperty('payloadBase64').GetString()) 'CATALOG_PAYLOAD_BLOCKED'
        if ($payloadBytes.Length -le 0 -or $payloadBytes.Length -gt $script:MaximumPayloadBytes) {
            Throw-PublisherBlocker 'CATALOG_PAYLOAD_BLOCKED'
        }
        $signature = ConvertFrom-CanonicalBase64 `
            ($root.GetProperty('signatureBase64').GetString()) 'CATALOG_SIGNATURE_BLOCKED'
        if ($signature.Length -ne 64) { Throw-PublisherBlocker 'CATALOG_SIGNATURE_BLOCKED' }
        $ecdsa = [Security.Cryptography.ECDsa]::Create()
        try {
            $read = 0
            $ecdsa.ImportSubjectPublicKeyInfo($spki, [ref]$read)
            if ($read -ne $spki.Length -or
                -not $ecdsa.VerifyData(
                    $payloadBytes,
                    $signature,
                    [Security.Cryptography.HashAlgorithmName]::SHA256,
                    [Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)) {
                Throw-PublisherBlocker 'CATALOG_SIGNATURE_BLOCKED'
            }
        }
        finally { $ecdsa.Dispose() }
    }
    catch {
        if ((Get-CatalogPublisherBlocker $_.Exception) -ne 'INVALID_ARGUMENT_BLOCKED') { throw }
        Throw-PublisherBlocker 'CATALOG_ENVELOPE_BLOCKED'
    }
    finally { $document.Dispose() }

    $payloadJson = ConvertFrom-StrictUtf8 $payloadBytes 'CATALOG_PAYLOAD_BLOCKED'
    try {
        $payloadDocument = [Text.Json.JsonDocument]::Parse($payloadJson, [Text.Json.JsonDocumentOptions]@{
                AllowTrailingCommas = $false
                CommentHandling = [Text.Json.JsonCommentHandling]::Disallow
                MaxDepth = 16
            })
    }
    catch { Throw-PublisherBlocker 'CATALOG_PAYLOAD_BLOCKED' }
    try {
        $payloadRoot = $payloadDocument.RootElement
        Assert-NoDuplicateJsonProperties $payloadRoot
        if (-not (Test-ExactJsonFields $payloadRoot @(
                    'schemaVersion', 'catalogVersion', 'sequence', 'issuedAt', 'expiresAt', 'providers'))) {
            Throw-PublisherBlocker 'CATALOG_PAYLOAD_BLOCKED'
        }
        if ($payloadRoot.GetProperty('schemaVersion').GetInt32() -ne 2 -or
            $payloadRoot.GetProperty('catalogVersion').GetString() -cne $script:CatalogVersion) {
            Throw-PublisherBlocker 'CATALOG_PAYLOAD_BLOCKED'
        }
        $sequence = $payloadRoot.GetProperty('sequence').GetInt64()
        if ($sequence -le 0) { Throw-PublisherBlocker 'CATALOG_PAYLOAD_BLOCKED' }
        $issuedAt = [datetimeoffset]::ParseExact(
            $payloadRoot.GetProperty('issuedAt').GetString(),
            'yyyy-MM-ddTHH:mm:ssZ',
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal)
        $expiresAt = [datetimeoffset]::ParseExact(
            $payloadRoot.GetProperty('expiresAt').GetString(),
            'yyyy-MM-ddTHH:mm:ssZ',
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal)
        if ($issuedAt -gt $Now.AddMinutes(10) -or
            $expiresAt -le $issuedAt -or
            $expiresAt - $issuedAt -gt [timespan]::FromDays(180)) {
            Throw-PublisherBlocker 'CATALOG_PAYLOAD_BLOCKED'
        }
        if (-not $AllowExpired -and $expiresAt -le $Now) {
            Throw-PublisherBlocker 'CATALOG_EXPIRED_BLOCKED'
        }
        $providers = $payloadRoot.GetProperty('providers')
        if ($providers.ValueKind -ne [Text.Json.JsonValueKind]::Array -or $providers.GetArrayLength() -ne 4) {
            Throw-PublisherBlocker 'CATALOG_PAYLOAD_BLOCKED'
        }
        $providerIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($provider in $providers.EnumerateArray()) {
            if (-not (Test-ExactJsonFields $provider @('id', 'models'))) {
                Throw-PublisherBlocker 'CATALOG_PAYLOAD_BLOCKED'
            }
            $providerId = $provider.GetProperty('id').GetString()
            if ($script:ExpectedProviderIds -cnotcontains $providerId -or -not $providerIds.Add($providerId)) {
                Throw-PublisherBlocker 'CATALOG_PAYLOAD_BLOCKED'
            }
            $models = $provider.GetProperty('models')
            if ($models.ValueKind -ne [Text.Json.JsonValueKind]::Array -or
                $models.GetArrayLength() -gt $script:MaximumModelsPerProvider) {
                Throw-PublisherBlocker 'CATALOG_PAYLOAD_BLOCKED'
            }
        }
    }
    catch {
        if ((Get-CatalogPublisherBlocker $_.Exception) -ne 'INVALID_ARGUMENT_BLOCKED') { throw }
        Throw-PublisherBlocker 'CATALOG_PAYLOAD_BLOCKED'
    }
    finally { $payloadDocument.Dispose() }

    try { $payload = $payloadJson | ConvertFrom-Json -AsHashtable -Depth 20 }
    catch { Throw-PublisherBlocker 'CATALOG_PAYLOAD_BLOCKED' }
    return [pscustomobject]@{
        EnvelopeBytes = $EnvelopeBytes
        EnvelopeSha256 = Get-Sha256Hex $EnvelopeBytes
        PayloadBytes = $payloadBytes
        PayloadSha256 = Get-Sha256Hex $payloadBytes
        Payload = $payload
        Sequence = [long]$sequence
        IssuedAt = $issuedAt.ToUniversalTime()
        ExpiresAt = $expiresAt.ToUniversalTime()
        KeyId = $keyId
    }
}

function Read-VerifiedProviderCatalogFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [datetimeoffset]$Now = [datetimeoffset]::UtcNow,
        [switch]$AllowExpired)
    try {
        $fullPath = [IO.Path]::GetFullPath($Path)
        $info = Get-Item -LiteralPath $fullPath -ErrorAction Stop
        if ($info.Length -le 0 -or $info.Length -gt $script:MaximumEnvelopeBytes) {
            Throw-PublisherBlocker 'CATALOG_ENVELOPE_BLOCKED'
        }
        $bytes = [IO.File]::ReadAllBytes($fullPath)
    }
    catch {
        if ((Get-CatalogPublisherBlocker $_.Exception) -ne 'INVALID_ARGUMENT_BLOCKED') { throw }
        Throw-PublisherBlocker 'CATALOG_ENVELOPE_BLOCKED'
    }
    return Read-VerifiedProviderCatalogBytes $bytes -Now $Now -AllowExpired:$AllowExpired
}

function Invoke-BoundedHttpsGet {
    param(
        [Parameter(Mandatory)][uri]$Uri,
        [int]$MaximumBytes = $script:MaximumSourceBytes,
        [timespan]$Timeout = [timespan]::FromSeconds(30))
    if ($Uri.Scheme -cne 'https') { Throw-PublisherBlocker 'SOURCE_DOWNLOAD_BLOCKED' }
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $client = [Net.Http.HttpClient]::new($handler)
    $client.Timeout = $Timeout
    $client.DefaultRequestHeaders.UserAgent.ParseAdd('TaskPilotSignalCatalogPublisher/1.2')
    try {
        try {
            $response = $client.GetAsync(
                $Uri,
                [Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        }
        catch { Throw-PublisherBlocker 'SOURCE_DOWNLOAD_BLOCKED' }
        try {
            if ($response.StatusCode -ne [Net.HttpStatusCode]::OK) {
                Throw-PublisherBlocker 'SOURCE_DOWNLOAD_BLOCKED'
            }
            $contentLength = $response.Content.Headers.ContentLength
            if ($null -ne $contentLength -and [long]$contentLength -gt $MaximumBytes) {
                Throw-PublisherBlocker 'SOURCE_DOWNLOAD_BLOCKED'
            }
            $stream = $response.Content.ReadAsStream()
            try {
                $buffer = [byte[]]::new(8192)
                $memory = [IO.MemoryStream]::new()
                try {
                    while (($count = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                        if ($memory.Length + $count -gt $MaximumBytes) {
                            Throw-PublisherBlocker 'SOURCE_DOWNLOAD_BLOCKED'
                        }
                        $memory.Write($buffer, 0, $count)
                    }
                    return ,($memory.ToArray())
                }
                finally { $memory.Dispose() }
            }
            finally { $stream.Dispose() }
        }
        finally { $response.Dispose() }
    }
    finally { $client.Dispose(); $handler.Dispose() }
}

function Resolve-PublisherCommand {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Blocker)
    $command = Get-Command $Name -CommandType Application,ExternalScript -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -eq $command -or [string]::IsNullOrWhiteSpace($command.Source)) {
        Throw-PublisherBlocker $Blocker
    }
    $path = [IO.Path]::GetFullPath($command.Source)
    if (-not [IO.Path]::IsPathFullyQualified($path) -or -not [IO.File]::Exists($path)) {
        Throw-PublisherBlocker $Blocker
    }
    return $path
}

function New-CommandStartInfo {
    param(
        [Parameter(Mandatory)][string]$CommandPath,
        [string[]]$Arguments = @())
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    if ([IO.Path]::GetExtension($CommandPath) -ieq '.ps1') {
        $startInfo.FileName = Resolve-PublisherCommand 'pwsh' 'DISCOVERY_RESULT_BLOCKED'
        foreach ($argument in @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $CommandPath) + $Arguments) {
            [void]$startInfo.ArgumentList.Add($argument)
        }
    }
    else {
        $startInfo.FileName = $CommandPath
        foreach ($argument in $Arguments) { [void]$startInfo.ArgumentList.Add($argument) }
    }
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    return $startInfo
}

function Read-CodexResponse {
    param(
        [Parameter(Mandatory)][Diagnostics.Process]$Process,
        [Parameter(Mandatory)][long]$ExpectedId,
        [Parameter(Mandatory)][datetime]$Deadline)
    while ([datetime]::UtcNow -lt $Deadline) {
        try {
            $line = $Process.StandardOutput.ReadLineAsync().WaitAsync(
                [timespan]::FromSeconds(5)).GetAwaiter().GetResult()
        }
        catch { Throw-PublisherBlocker 'CODEX_DISCOVERY_BLOCKED' }
        if ($null -eq $line -or $line.Length -gt 262144) { Throw-PublisherBlocker 'CODEX_DISCOVERY_BLOCKED' }
        try { $message = $line | ConvertFrom-Json -AsHashtable -Depth 20 }
        catch { Throw-PublisherBlocker 'CODEX_DISCOVERY_BLOCKED' }
        if (-not $message.ContainsKey('id')) { continue }
        if ([long]$message['id'] -ne $ExpectedId -or
            $message.ContainsKey('error') -or
            -not $message.ContainsKey('result')) {
            Throw-PublisherBlocker 'CODEX_DISCOVERY_BLOCKED'
        }
        return $message['result']
    }
    Throw-PublisherBlocker 'CODEX_DISCOVERY_BLOCKED'
}

function Get-CodexDiscoveredModels {
    [CmdletBinding()]
    param()
    $commandPath = Resolve-PublisherCommand 'codex' 'CODEX_DISCOVERY_BLOCKED'
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = New-CommandStartInfo $commandPath @('app-server')
    $stderrTask = $null
    try {
        if (-not $process.Start()) { Throw-PublisherBlocker 'CODEX_DISCOVERY_BLOCKED' }
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $deadline = [datetime]::UtcNow.AddSeconds(45)
        $process.StandardInput.WriteLine('{"method":"initialize","id":1,"params":{"clientInfo":{"name":"TaskPilotSignalCatalogPublisher","title":"TaskPilotSignal Catalog Publisher","version":"1.2.0.0"}}}')
        $process.StandardInput.Flush()
        [void](Read-CodexResponse $process 1 $deadline)
        $process.StandardInput.WriteLine('{"method":"initialized","params":{}}')
        $process.StandardInput.Flush()

        $models = [Collections.Generic.List[object]]::new()
        $unique = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $cursor = $null
        $requestId = 1L
        for ($page = 0; $page -lt 20; $page++) {
            $requestId++
            $request = [ordered]@{
                method = 'model/list'
                id = $requestId
                params = [ordered]@{ limit = 100; includeHidden = $false; cursor = $cursor }
            } | ConvertTo-Json -Compress -Depth 5
            $process.StandardInput.WriteLine($request)
            $process.StandardInput.Flush()
            $result = Read-CodexResponse $process $requestId $deadline
            if (-not $result.ContainsKey('data') -or $result['data'] -isnot [Collections.IEnumerable]) {
                Throw-PublisherBlocker 'CODEX_DISCOVERY_BLOCKED'
            }
            foreach ($model in @($result['data'])) {
                $id = [string]$model['id']
                $display = [string]$model['model']
                if (-not (Test-SafeLabel $id) -or -not (Test-SafeLabel $display)) {
                    Throw-PublisherBlocker 'CODEX_DISCOVERY_BLOCKED'
                }
                if ($model.ContainsKey('hidden') -and [bool]$model['hidden']) { continue }
                if (-not $unique.Add($id)) { Throw-PublisherBlocker 'CODEX_DISCOVERY_BLOCKED' }
                $efforts = [Collections.Generic.List[string]]::new()
                foreach ($effortItem in @($model['supportedReasoningEfforts'])) {
                    $effort = [string]$effortItem['reasoningEffort']
                    if ($script:AllowedEfforts -cnotcontains $effort -or $efforts.Contains($effort)) {
                        Throw-PublisherBlocker 'CODEX_DISCOVERY_BLOCKED'
                    }
                    $efforts.Add($effort)
                }
                $defaultEffort = if ($null -eq $model['defaultReasoningEffort']) {
                    $null
                }
                else { [string]$model['defaultReasoningEffort'] }
                if ($null -ne $defaultEffort -and -not $efforts.Contains($defaultEffort)) {
                    Throw-PublisherBlocker 'CODEX_DISCOVERY_BLOCKED'
                }
                $models.Add([ordered]@{
                        id = $id
                        aliases = if ($id -ceq $display) { @() } else { @($display) }
                        supportedEfforts = $efforts.ToArray()
                        defaultEffort = $defaultEffort
                    })
                if ($models.Count -gt $script:MaximumModelsPerProvider) {
                    Throw-PublisherBlocker 'CODEX_DISCOVERY_BLOCKED'
                }
            }
            $cursor = if ($result.ContainsKey('nextCursor')) { $result['nextCursor'] } else { $null }
            if ($null -eq $cursor) { break }
            if ($cursor -isnot [string] -or $cursor.Length -le 0 -or $cursor.Length -gt 512 -or
                $cursor.ToCharArray().Where({ [char]::IsControl($_) }, 'First')) {
                Throw-PublisherBlocker 'CODEX_DISCOVERY_BLOCKED'
            }
            if ($page -eq 19) { Throw-PublisherBlocker 'CODEX_DISCOVERY_BLOCKED' }
        }
        if ($models.Count -le 0) { Throw-PublisherBlocker 'CODEX_DISCOVERY_BLOCKED' }
        return $models.ToArray()
    }
    catch {
        if ((Get-CatalogPublisherBlocker $_.Exception) -ne 'INVALID_ARGUMENT_BLOCKED') { throw }
        Throw-PublisherBlocker 'CODEX_DISCOVERY_BLOCKED'
    }
    finally {
        try { $process.StandardInput.Close() } catch { }
        try {
            if (-not $process.HasExited) { $process.Kill($true); [void]$process.WaitForExit(5000) }
        }
        catch { }
        if ($null -ne $stderrTask -and $stderrTask.IsCompletedSuccessfully -and
            [Text.Encoding]::UTF8.GetByteCount($stderrTask.Result) -gt 65536) {
            # Deliberately do not surface provider stderr.
        }
        $process.Dispose()
    }
}

function Get-AntigravityDiscoveredModels {
    [CmdletBinding()]
    param()
    $commandPath = Resolve-PublisherCommand 'agy' 'DISCOVERY_RESULT_BLOCKED'
    if ([IO.Path]::GetFileName($commandPath) -ine 'agy.exe') {
        Throw-PublisherBlocker 'DISCOVERY_RESULT_BLOCKED'
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = New-CommandStartInfo $commandPath @('models')
    try {
        if (-not $process.Start()) { Throw-PublisherBlocker 'DISCOVERY_RESULT_BLOCKED' }
        $process.StandardInput.Close()
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        try { [void]$process.WaitForExitAsync().WaitAsync([timespan]::FromSeconds(45)).GetAwaiter().GetResult() }
        catch { Throw-PublisherBlocker 'DISCOVERY_RESULT_BLOCKED' }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0 -or
            [Text.Encoding]::UTF8.GetByteCount($stdout) -gt 65536 -or
            [Text.Encoding]::UTF8.GetByteCount($stderr) -gt 65536) {
            Throw-PublisherBlocker 'DISCOVERY_RESULT_BLOCKED'
        }
        $models = [Collections.Generic.List[object]]::new()
        $ids = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $labels = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($line in [regex]::Split($stdout, '\r?\n')) {
            if ($line.Length -eq 0) { continue }
            if ($line.Length -gt 300 -or $line -cne $line.Trim()) {
                Throw-PublisherBlocker 'DISCOVERY_RESULT_BLOCKED'
            }
            $parts = $line.Split("`t")
            if ($parts.Count -ne 2) { Throw-PublisherBlocker 'DISCOVERY_RESULT_BLOCKED' }
            $id = $parts[0]
            $label = $parts[1]
            if (-not $script:SafeModelIdPattern.IsMatch($id) -or -not (Test-SafeLabel $label) -or
                -not $ids.Add($id) -or -not $labels.Add($label)) {
                Throw-PublisherBlocker 'DISCOVERY_RESULT_BLOCKED'
            }
            $models.Add([ordered]@{ id = $label; cliId = $id })
            if ($models.Count -gt $script:MaximumModelsPerProvider) {
                Throw-PublisherBlocker 'DISCOVERY_RESULT_BLOCKED'
            }
        }
        if ($models.Count -le 0) { Throw-PublisherBlocker 'DISCOVERY_RESULT_BLOCKED' }
        return $models.ToArray()
    }
    catch {
        if ((Get-CatalogPublisherBlocker $_.Exception) -ne 'INVALID_ARGUMENT_BLOCKED') { throw }
        Throw-PublisherBlocker 'DISCOVERY_RESULT_BLOCKED'
    }
    finally {
        try {
            if (-not $process.HasExited) { $process.Kill($true); [void]$process.WaitForExit(5000) }
        }
        catch { }
        $process.Dispose()
    }
}

function ConvertFrom-ClaudeModelsMarkdown {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Markdown)
    if ($Markdown.Length -le 0 -or [Text.Encoding]::UTF8.GetByteCount($Markdown) -gt $script:MaximumSourceBytes) {
        Throw-PublisherBlocker 'CLAUDE_DISCOVERY_BLOCKED'
    }
    $lines = [regex]::Split($Markdown, '\r?\n')
    $start = [Array]::IndexOf($lines, '## Current Models (recommended)')
    if ($start -lt 0) { Throw-PublisherBlocker 'CLAUDE_DISCOVERY_BLOCKED' }
    $pattern = [regex]::new(
        '^\|\s*(?<friendly>[^|]+?)\s*\|\s*`(?<id>claude-[a-z0-9-]+)`\s*\|\s*(?<full>[^|]*?)\s*\|\s*(?<context>[^|]*?)\s*\|\s*(?<output>[^|]*?)\s*\|\s*(?<status>[^|]+?)\s*\|$',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant)
    $models = [Collections.Generic.List[object]]::new()
    $ids = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    for ($index = $start + 1; $index -lt $lines.Count; $index++) {
        $line = $lines[$index]
        if ($line.StartsWith('### ', [StringComparison]::Ordinal)) { break }
        $match = $pattern.Match($line)
        if (-not $match.Success) { continue }
        $status = $match.Groups['status'].Value.Trim()
        if ($status -cne 'Active') { continue }
        $id = $match.Groups['id'].Value
        $friendly = $match.Groups['friendly'].Value.Trim()
        if (-not $script:SafeModelIdPattern.IsMatch($id) -or
            -not $id.StartsWith('claude-', [StringComparison]::Ordinal) -or
            -not (Test-SafeLabel $friendly) -or
            -not $ids.Add($id)) {
            Throw-PublisherBlocker 'CLAUDE_DISCOVERY_BLOCKED'
        }
        $models.Add([ordered]@{ id = $id; friendlyName = $friendly })
    }
    if ($models.Count -lt 3 -or
        -not @($models | Where-Object { $_['id'] -match '^claude-opus-' }).Count -or
        -not @($models | Where-Object { $_['id'] -match '^claude-sonnet-' }).Count -or
        -not @($models | Where-Object { $_['id'] -match '^claude-haiku-' }).Count) {
        Throw-PublisherBlocker 'CLAUDE_DISCOVERY_BLOCKED'
    }
    return $models.ToArray()
}

function Get-ClaudeDiscoveredModels {
    [CmdletBinding()]
    param()
    try {
        $bytes = Invoke-BoundedHttpsGet ([uri]$script:ClaudeModelsUrl)
        $markdown = ConvertFrom-StrictUtf8 $bytes 'CLAUDE_DISCOVERY_BLOCKED'
        return ConvertFrom-ClaudeModelsMarkdown $markdown
    }
    catch {
        if ((Get-CatalogPublisherBlocker $_.Exception) -ne 'INVALID_ARGUMENT_BLOCKED') { throw }
        Throw-PublisherBlocker 'CLAUDE_DISCOVERY_BLOCKED'
    }
}

function Get-ProviderEntry {
    param(
        [Parameter(Mandatory)][Collections.IDictionary]$Payload,
        [Parameter(Mandatory)][string]$ProviderId)
    $provider = @($Payload['providers'] | Where-Object { $_['id'] -ceq $ProviderId })
    if ($provider.Count -ne 1) { Throw-PublisherBlocker 'MODEL_MERGE_BLOCKED' }
    return $provider[0]
}

function New-ProviderSymbolTable {
    param([Parameter(Mandatory)][object[]]$Models)
    $symbols = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($model in $Models) {
        foreach ($symbol in @([string]$model['id']) + @($model['aliases'] | ForEach-Object { [string]$_ })) {
            if (-not (Test-SafeLabel $symbol) -or $symbols.ContainsKey($symbol)) {
                Throw-PublisherBlocker 'MODEL_MERGE_BLOCKED'
            }
            $symbols.Add($symbol, $model)
        }
    }
    return $symbols
}

function New-CatalogModel {
    param(
        [Parameter(Mandatory)][string]$Id,
        [string[]]$Aliases = @(),
        [string[]]$SupportedEfforts = @(),
        [AllowNull()][string]$DefaultEffort = $null)
    return [ordered]@{
        id = $Id
        status = 'active'
        replacement = $null
        aliases = @($Aliases)
        supportedEfforts = @($SupportedEfforts)
        defaultEffort = $DefaultEffort
    }
}

function Merge-ProviderModelDiscoveries {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][Collections.IDictionary]$Payload,
        [Parameter(Mandatory)][object[]]$CodexModels,
        [Parameter(Mandatory)][object[]]$AntigravityModels,
        [Parameter(Mandatory)][object[]]$ClaudeModels)

    try {
        $clone = (($Payload | ConvertTo-Json -Compress -Depth 20) | ConvertFrom-Json -AsHashtable -Depth 20)
        $newModels = [ordered]@{ antigravity = @(); claude = @(); codex = @() }
        $changed = $false

        $codex = Get-ProviderEntry $clone 'codex'
        $codexExisting = @($codex['models'])
        $codexSymbols = New-ProviderSymbolTable $codexExisting
        $codexAdded = [Collections.Generic.List[object]]::new()
        foreach ($discovered in $CodexModels) {
            $id = [string]$discovered['id']
            if ($codexSymbols.ContainsKey($id)) { continue }
            $model = New-CatalogModel `
                $id @($discovered['aliases']) @($discovered['supportedEfforts']) $discovered['defaultEffort']
            $codexAdded.Add($model)
            $codexSymbols.Add($id, $model)
            foreach ($alias in @($model['aliases'])) { $codexSymbols.Add([string]$alias, $model) }
            $newModels['codex'] += $id
            $changed = $true
        }
        if ($codexAdded.Count) { $codex['models'] = @($codexAdded.ToArray()) + $codexExisting }

        $antigravity = Get-ProviderEntry $clone 'antigravity'
        $antigravityExisting = @($antigravity['models'])
        $antigravitySymbols = New-ProviderSymbolTable $antigravityExisting
        $antigravityAdded = [Collections.Generic.List[object]]::new()
        foreach ($discovered in $AntigravityModels) {
            $id = [string]$discovered['id']
            $cliId = [string]$discovered['cliId']
            if ($antigravitySymbols.ContainsKey($id)) {
                $existing = $antigravitySymbols[$id]
                if (@($existing['aliases']) -inotcontains $cliId) {
                    if ($antigravitySymbols.ContainsKey($cliId)) { Throw-PublisherBlocker 'MODEL_MERGE_BLOCKED' }
                    $existing['aliases'] = @($existing['aliases']) + @($cliId)
                    $antigravitySymbols.Add($cliId, $existing)
                    $changed = $true
                }
                continue
            }
            if ($antigravitySymbols.ContainsKey($cliId)) { continue }
            $model = New-CatalogModel $id @($cliId)
            $antigravityAdded.Add($model)
            $antigravitySymbols.Add($id, $model)
            $antigravitySymbols.Add($cliId, $model)
            $newModels['antigravity'] += $id
            $changed = $true
        }
        if ($antigravityAdded.Count) {
            $antigravity['models'] = @($antigravityAdded.ToArray()) + $antigravityExisting
        }

        $claude = Get-ProviderEntry $clone 'claude'
        $claudeExisting = @($claude['models'])
        $claudeSymbols = New-ProviderSymbolTable $claudeExisting
        $claudeAdded = [Collections.Generic.List[object]]::new()
        foreach ($discovered in $ClaudeModels) {
            $id = [string]$discovered['id']
            if ($claudeSymbols.ContainsKey($id)) { continue }
            $aliases = [Collections.Generic.List[string]]::new()
            if ($id -match '^claude-(opus|sonnet|haiku|fable)-') {
                $family = $Matches[1]
                foreach ($existing in $claudeExisting) {
                    $filtered = @($existing['aliases'] | Where-Object {
                            -not [string]::Equals([string]$_, $family, [StringComparison]::OrdinalIgnoreCase)
                        })
                    if ($filtered.Count -ne @($existing['aliases']).Count) {
                        $existing['aliases'] = $filtered
                        [void]$claudeSymbols.Remove($family)
                        $changed = $true
                    }
                }
                if (-not $claudeSymbols.ContainsKey($family)) { $aliases.Add($family) }
            }
            $model = New-CatalogModel `
                $id $aliases.ToArray() @('low', 'medium', 'high', 'xhigh', 'max') 'medium'
            $claudeAdded.Add($model)
            $claudeSymbols.Add($id, $model)
            foreach ($alias in @($model['aliases'])) { $claudeSymbols.Add([string]$alias, $model) }
            $newModels['claude'] += $id
            $changed = $true
        }
        if ($claudeAdded.Count) { $claude['models'] = @($claudeAdded.ToArray()) + $claudeExisting }

        foreach ($providerId in @('codex', 'antigravity', 'claude')) {
            $provider = Get-ProviderEntry $clone $providerId
            if (@($provider['models']).Count -gt $script:MaximumModelsPerProvider) {
                Throw-PublisherBlocker 'MODEL_MERGE_BLOCKED'
            }
        }
        return [pscustomobject]@{
            Changed = $changed
            Payload = $clone
            NewModels = $newModels
        }
    }
    catch {
        if ((Get-CatalogPublisherBlocker $_.Exception) -ne 'INVALID_ARGUMENT_BLOCKED') { throw }
        Throw-PublisherBlocker 'MODEL_MERGE_BLOCKED'
    }
}

function Get-ProductionSigningIdentity {
    param([datetimeoffset]$Now = [datetimeoffset]::UtcNow)
    $store = [Security.Cryptography.X509Certificates.X509Store]::new('My', 'CurrentUser')
    $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    try {
        $expectedKeyId = Get-ExpectedCatalogKeyId
        $matches = [Collections.Generic.List[object]]::new()
        foreach ($certificate in @($store.Certificates | Where-Object {
                    $_.Subject -ceq 'CN=TaskPilotSignal Provider Model Catalog Production' -and $_.HasPrivateKey
                })) {
            $publicKey = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($certificate)
            try {
                if ($null -eq $publicKey) { continue }
                $keyId = 'sha256:' + (Get-Sha256Hex $publicKey.ExportSubjectPublicKeyInfo())
                if ($keyId -cne $expectedKeyId -or $certificate.NotAfter.ToUniversalTime() -le $Now.UtcDateTime) {
                    continue
                }
                $matches.Add([pscustomobject]@{
                        Thumbprint = $certificate.Thumbprint.ToUpperInvariant()
                        KeyId = $keyId
                        NotAfter = [datetimeoffset]$certificate.NotAfter.ToUniversalTime()
                    })
            }
            finally { if ($null -ne $publicKey) { $publicKey.Dispose() } }
        }
        if ($matches.Count -le 0) { Throw-PublisherBlocker 'SIGNING_IDENTITY_BLOCKED' }
        return $matches | Sort-Object NotAfter -Descending | Select-Object -First 1
    }
    finally { $store.Close(); $store.Dispose() }
}

function ConvertTo-CatalogPayloadBytes {
    param(
        [Parameter(Mandatory)][Collections.IDictionary]$Payload,
        [Parameter(Mandatory)][long]$Sequence,
        [Parameter(Mandatory)][datetimeoffset]$IssuedAt,
        [Parameter(Mandatory)][datetimeoffset]$ExpiresAt)
    $Payload['catalogVersion'] = $script:CatalogVersion
    $Payload['sequence'] = $Sequence
    $Payload['issuedAt'] = $IssuedAt.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $Payload['expiresAt'] = $ExpiresAt.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $json = $Payload | ConvertTo-Json -Compress -Depth 20
    $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($json)
    if ($bytes.Length -le 0 -or $bytes.Length -gt $script:MaximumPayloadBytes) {
        Throw-PublisherBlocker 'CATALOG_PAYLOAD_BLOCKED'
    }
    return ,$bytes
}

function Write-AtomicBytes {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][byte[]]$Bytes)
    try {
        $fullPath = [IO.Path]::GetFullPath($Path)
        $directory = [IO.Path]::GetDirectoryName($fullPath)
        [IO.Directory]::CreateDirectory($directory) | Out-Null
        $temporary = [IO.Path]::Combine($directory, ".catalog.$([guid]::NewGuid().ToString('N')).tmp")
        try {
            [IO.File]::WriteAllBytes($temporary, $Bytes)
            [IO.File]::Move($temporary, $fullPath, $true)
        }
        finally { if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) } }
    }
    catch { Throw-PublisherBlocker 'OUTPUT_WRITE_BLOCKED' }
}

function Invoke-CatalogSigner {
    param(
        [Parameter(Mandatory)][string]$SignerRepositoryPath,
        [Parameter(Mandatory)][string]$InputPath,
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)]$Identity)
    $signer = [IO.Path]::GetFullPath((Join-Path $SignerRepositoryPath 'scripts/sign_provider_model_catalog.ps1'))
    if (-not [IO.File]::Exists($signer)) { Throw-PublisherBlocker 'SIGNING_TOOL_BLOCKED' }
    $pwsh = Resolve-PublisherCommand 'pwsh' 'SIGNING_TOOL_BLOCKED'
    try {
        $resultLines = & $pwsh -NoLogo -NoProfile -NonInteractive -File $signer `
            -Mode Sign -Purpose Production `
            -CertificateThumbprint $Identity.Thumbprint `
            -ExpectedKeyId $Identity.KeyId `
            -InputPath $InputPath -OutputPath $OutputPath -Force 2>$null
        $exitCode = $LASTEXITCODE
        $result = ($resultLines | Select-Object -Last 1) | ConvertFrom-Json -AsHashtable -Depth 10
    }
    catch { Throw-PublisherBlocker 'SIGNING_TOOL_BLOCKED' }
    if ($exitCode -ne 0 -or $result['status'] -cne 'pass' -or $result['operation'] -cne 'sign') {
        Throw-PublisherBlocker 'SIGNING_TOOL_BLOCKED'
    }
    return $result
}

function Invoke-SafeGit {
    param(
        [Parameter(Mandatory)][string]$RepositoryPath,
        [Parameter(Mandatory)][string[]]$Arguments,
        [int]$TimeoutSeconds = 60)
    $git = Resolve-PublisherCommand 'git' 'GIT_WORKTREE_BLOCKED'
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $git
    $startInfo.WorkingDirectory = [IO.Path]::GetFullPath($RepositoryPath)
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in $Arguments) { [void]$startInfo.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) { Throw-PublisherBlocker 'GIT_WORKTREE_BLOCKED' }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        try { $process.WaitForExitAsync().WaitAsync([timespan]::FromSeconds($TimeoutSeconds)).GetAwaiter().GetResult() }
        catch { Throw-PublisherBlocker 'GIT_WORKTREE_BLOCKED' }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ([Text.Encoding]::UTF8.GetByteCount($stdout) -gt 262144 -or
            [Text.Encoding]::UTF8.GetByteCount($stderr) -gt 262144) {
            Throw-PublisherBlocker 'GIT_WORKTREE_BLOCKED'
        }
        return [pscustomobject]@{ ExitCode = $process.ExitCode; Stdout = $stdout }
    }
    finally {
        try {
            if (-not $process.HasExited) { $process.Kill($true); [void]$process.WaitForExit(5000) }
        }
        catch { }
        $process.Dispose()
    }
}

function Assert-CatalogGitBoundary {
    param([Parameter(Mandatory)][string]$PagesRepositoryPath)
    $status = Invoke-SafeGit $PagesRepositoryPath @('status', '--porcelain=v1', '--untracked-files=all')
    if ($status.ExitCode -ne 0) { Throw-PublisherBlocker 'GIT_WORKTREE_BLOCKED' }
    $unexpected = @([regex]::Split($status.Stdout.TrimEnd(), '\r?\n') | Where-Object {
            $_.Length -gt 0 -and $_ -cne '?? provider-models.v2.payload.json'
        })
    if ($unexpected.Count -gt 0) { Throw-PublisherBlocker 'GIT_WORKTREE_BLOCKED' }
    $fetch = Invoke-SafeGit $PagesRepositoryPath @('fetch', '--quiet', 'origin', 'main') 120
    if ($fetch.ExitCode -ne 0) { Throw-PublisherBlocker 'GIT_DIVERGED_BLOCKED' }
    $divergence = Invoke-SafeGit $PagesRepositoryPath @(
        'rev-list', '--left-right', '--count', 'HEAD...origin/main')
    if ($divergence.ExitCode -ne 0 -or $divergence.Stdout.Trim() -cne "0`t0") {
        Throw-PublisherBlocker 'GIT_DIVERGED_BLOCKED'
    }
}

function Publish-CatalogCandidate {
    param(
        [Parameter(Mandatory)][string]$PagesRepositoryPath,
        [Parameter(Mandatory)][string]$CandidatePath,
        [Parameter(Mandatory)][long]$Sequence)
    $target = [IO.Path]::GetFullPath((Join-Path $PagesRepositoryPath 'provider-models.v2.signed.json'))
    $bytes = [IO.File]::ReadAllBytes($CandidatePath)
    Write-AtomicBytes $target $bytes
    $add = Invoke-SafeGit $PagesRepositoryPath @('add', '--', 'provider-models.v2.signed.json')
    if ($add.ExitCode -ne 0) { Throw-PublisherBlocker 'GIT_COMMIT_BLOCKED' }
    $staged = Invoke-SafeGit $PagesRepositoryPath @('diff', '--cached', '--name-only', '--')
    if ($staged.ExitCode -ne 0 -or $staged.Stdout.Trim() -cne 'provider-models.v2.signed.json') {
        Throw-PublisherBlocker 'GIT_COMMIT_BLOCKED'
    }
    $commit = Invoke-SafeGit $PagesRepositoryPath @(
        'commit', '-m', "Publish provider model catalog sequence $Sequence", '--',
        'provider-models.v2.signed.json')
    if ($commit.ExitCode -ne 0) { Throw-PublisherBlocker 'GIT_COMMIT_BLOCKED' }
    $push = Invoke-SafeGit $PagesRepositoryPath @('push', 'origin', 'HEAD:main') 120
    if ($push.ExitCode -ne 0) { Throw-PublisherBlocker 'GIT_PUSH_BLOCKED' }
}

function Confirm-PublicCatalogSequence {
    param(
        [Parameter(Mandatory)][long]$Sequence,
        [int]$Attempts = 12)
    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        try {
            $uri = [uri]($script:CatalogUrl + '?sequence=' + $Sequence + '&attempt=' + $attempt + '&t=' + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
            $bytes = Invoke-BoundedHttpsGet $uri $script:MaximumEnvelopeBytes ([timespan]::FromSeconds(20))
            $catalog = Read-VerifiedProviderCatalogBytes $bytes
            if ($catalog.Sequence -eq $Sequence) { return $catalog }
            if ($catalog.Sequence -gt $Sequence) { Throw-PublisherBlocker 'CATALOG_ROLLBACK_BLOCKED' }
        }
        catch {
            if ((Get-CatalogPublisherBlocker $_.Exception) -eq 'CATALOG_ROLLBACK_BLOCKED') { throw }
        }
        if ($attempt -lt $Attempts) { Start-Sleep -Seconds 10 }
    }
    Throw-PublisherBlocker 'PUBLICATION_READBACK_BLOCKED'
}

function Invoke-ProviderModelCatalogPreview {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PagesRepositoryPath,
        [Parameter(Mandatory)][string]$SignerRepositoryPath,
        [Parameter(Mandatory)][string]$EvidenceRoot,
        [datetimeoffset]$Now = [datetimeoffset]::UtcNow,
        [switch]$Publish)

    $pages = [IO.Path]::GetFullPath($PagesRepositoryPath)
    $signerRepo = [IO.Path]::GetFullPath($SignerRepositoryPath)
    $evidence = [IO.Path]::GetFullPath($EvidenceRoot)
    $catalogPath = Join-Path $pages 'provider-models.v2.signed.json'
    $current = Read-VerifiedProviderCatalogFile $catalogPath -Now $Now
    $codexModels = Get-CodexDiscoveredModels
    $antigravityModels = Get-AntigravityDiscoveredModels
    $claudeModels = Get-ClaudeDiscoveredModels
    $merged = Merge-ProviderModelDiscoveries `
        $current.Payload $codexModels $antigravityModels $claudeModels
    $renewalRequired = $current.ExpiresAt -le $Now.AddDays(45)
    if (-not $merged.Changed -and -not $renewalRequired) {
        return [pscustomobject]@{
            Status = 'pass'
            Operation = if ($Publish) { 'publish-no-change' } else { 'preview-no-change' }
            ChangeRequired = $false
            Sequence = $current.Sequence
            ExpiresAt = $current.ExpiresAt
            EnvelopeSha256 = $current.EnvelopeSha256
            NewModels = $merged.NewModels
        }
    }

    if ($Publish) { Assert-CatalogGitBoundary $pages }
    $identity = Get-ProductionSigningIdentity $Now
    $issuedAt = [datetimeoffset]::new(
        $Now.UtcDateTime.Year, $Now.UtcDateTime.Month, $Now.UtcDateTime.Day,
        $Now.UtcDateTime.Hour, $Now.UtcDateTime.Minute, $Now.UtcDateTime.Second,
        [timespan]::Zero)
    $desiredExpiry = $issuedAt.AddDays(150)
    $certificateLimit = $identity.NotAfter.AddDays(-1)
    $expiresAt = if ($desiredExpiry -le $certificateLimit) { $desiredExpiry } else { $certificateLimit }
    if ($expiresAt -le $issuedAt.AddDays(60)) { Throw-PublisherBlocker 'CERT_RENEWAL_REQUIRED' }
    $nextSequence = [long]$current.Sequence + 1
    $payloadBytes = ConvertTo-CatalogPayloadBytes `
        $merged.Payload $nextSequence $issuedAt $expiresAt
    [IO.Directory]::CreateDirectory($evidence) | Out-Null
    $payloadPath = Join-Path $evidence "provider-models.sequence-$nextSequence.payload.json"
    $candidatePath = Join-Path $evidence "provider-models.sequence-$nextSequence.signed.json"
    Write-AtomicBytes $payloadPath $payloadBytes
    [void](Invoke-CatalogSigner $signerRepo $payloadPath $candidatePath $identity)
    $candidate = Read-VerifiedProviderCatalogFile $candidatePath -Now $Now
    if ($candidate.Sequence -ne $nextSequence -or $candidate.Sequence -le $current.Sequence) {
        Throw-PublisherBlocker 'CATALOG_ROLLBACK_BLOCKED'
    }

    if ($Publish) {
        Publish-CatalogCandidate $pages $candidatePath $nextSequence
        $public = Confirm-PublicCatalogSequence $nextSequence
        return [pscustomobject]@{
            Status = 'pass'
            Operation = 'publish'
            ChangeRequired = $true
            Sequence = $public.Sequence
            ExpiresAt = $public.ExpiresAt
            EnvelopeSha256 = $public.EnvelopeSha256
            NewModels = $merged.NewModels
        }
    }
    return [pscustomobject]@{
        Status = 'pass'
        Operation = 'preview'
        ChangeRequired = $true
        Sequence = $candidate.Sequence
        ExpiresAt = $candidate.ExpiresAt
        EnvelopeSha256 = $candidate.EnvelopeSha256
        CandidatePath = $candidatePath
        NewModels = $merged.NewModels
    }
}

function Test-PublicProviderModelCatalog {
    [CmdletBinding()]
    param(
        [int]$MinimumRemainingDays = 30,
        [datetimeoffset]$Now = [datetimeoffset]::UtcNow)
    try {
        $uri = [uri]($script:CatalogUrl + '?monitor=' + $Now.ToUnixTimeSeconds())
        $bytes = Invoke-BoundedHttpsGet $uri $script:MaximumEnvelopeBytes ([timespan]::FromSeconds(30))
        $catalog = Read-VerifiedProviderCatalogBytes $bytes -Now $Now
        if ($catalog.ExpiresAt -le $Now.AddDays($MinimumRemainingDays)) {
            Throw-PublisherBlocker 'CATALOG_MONITOR_BLOCKED'
        }
        return [pscustomobject]@{
            Status = 'pass'
            Operation = 'monitor'
            Sequence = $catalog.Sequence
            ExpiresAt = $catalog.ExpiresAt
            EnvelopeSha256 = $catalog.EnvelopeSha256
        }
    }
    catch {
        if ((Get-CatalogPublisherBlocker $_.Exception) -ne 'INVALID_ARGUMENT_BLOCKED') { throw }
        Throw-PublisherBlocker 'CATALOG_MONITOR_BLOCKED'
    }
}

Export-ModuleMember -Function @(
    'ConvertFrom-ClaudeModelsMarkdown',
    'Get-CatalogPublisherBlocker',
    'Get-ExpectedCatalogKeyId',
    'Merge-ProviderModelDiscoveries',
    'Read-VerifiedProviderCatalogBytes',
    'Read-VerifiedProviderCatalogFile',
    'Invoke-ProviderModelCatalogPreview',
    'Test-PublicProviderModelCatalog',
    'Write-AtomicBytes')
