# ---------------------------------------------------------------------------
# Firmware catalog client. Asks the hosted catalog service for the BIOS
# releases of this model, caches the answer under the data root, and falls
# back to the cached copy when the service cannot be reached.
# ---------------------------------------------------------------------------

function Get-CEFirmwareCatalogKey {
    <# Vendor and model id the catalog is keyed by, or $null for unsupported makes. #>
    param($Hardware)
    if ($null -eq $Hardware) { return $null }
    $maker = [string](Get-CEObjectValue $Hardware 'Manufacturer' '')
    $id = $null
    $vendor = $null
    if ($maker -match '^Dell') {
        $vendor = 'dell'
        $id = [string](Get-CEObjectValue $Hardware 'SystemSku' '')
    }
    elseif ($maker -match '^(HP|Hewlett)') {
        $vendor = 'hp'
        $id = [string](Get-CEObjectValue $Hardware 'BaseboardProduct' '')
    }
    elseif ($maker -match '^LENOVO') {
        $vendor = 'lenovo'
        # Windows reports the model as the machine type plus configuration, e.g. 21KCCTO1WW.
        $model = [string](Get-CEObjectValue $Hardware 'Model' '')
        $sku = [string](Get-CEObjectValue $Hardware 'SystemSku' '')
        if ($model -match '^([0-9A-Za-z]{4})') { $id = $Matches[1] }
        elseif ($sku -match 'MT_([0-9A-Za-z]{4})') { $id = $Matches[1] }
    }
    if (-not $vendor -or -not $id -or $id.Trim() -notmatch '^[0-9A-Za-z]{4}$') { return $null }
    return [pscustomobject]@{ Vendor = $vendor; Id = $id.Trim().ToUpperInvariant() }
}

function Compare-CEVersionFull {
    <# -1, 0 or 1 comparing dotted numeric versions, padding with zeros. #>
    param([long[]]$Left, [long[]]$Right)
    for ($i = 0; $i -lt [math]::Max($Left.Count, $Right.Count); $i++) {
        $a = if ($i -lt $Left.Count) { $Left[$i] } else { 0 }
        $b = if ($i -lt $Right.Count) { $Right[$i] } else { 0 }
        if ($a -lt $b) { return -1 }
        if ($a -gt $b) { return 1 }
    }
    return 0
}

function Compare-CEFirmwareVersion {
    <#
        Compares the BIOS version Windows reports with a catalog version.
        Returns -1 (installed is older), 0, 1, or $null when they can't be compared.
    #>
    param([Parameter(Mandatory)][string]$Vendor, [AllowEmptyString()][string]$Installed, [AllowEmptyString()][string]$Catalog)
    $inst = "$Installed".Trim()
    $cat = "$Catalog".Trim()
    if (-not $inst -or -not $cat) { return $null }
    $numeric = {
        param($a, $b)
        $x = ConvertTo-CEVersionPart $a
        $y = ConvertTo-CEVersionPart $b
        if ($x.Count -eq 0 -or $y.Count -eq 0) { return $null }
        return (Compare-CEVersionFull $x $y)
    }
    switch ($Vendor) {
        'dell' { return (& $numeric $inst $cat) }
        'hp' {
            # Windows reports e.g. 'V70 Ver. 01.13.01'; the catalog has '01.13.01'.
            if ($inst -match '(\d+(\.\d+)+)\s*$') { return (& $numeric $Matches[1] $cat) }
            return $null
        }
        'lenovo' {
            # ThinkPad: 'N3YET84W (1.49 )' against '1.50'. ThinkCentre: 'M11KT56A' against 'M11KT56A'.
            if ($cat -match '^\d+(\.\d+)+$') {
                if ($inst -match '\((\d+(\.\d+)+)') { return (& $numeric $Matches[1] $cat) }
                return $null
            }
            if ($inst -match '^([0-9A-Z]{3,5})T(\d+)' ) {
                $instPrefix = $Matches[1]; $instBuild = [int]$Matches[2]
                if ($cat -match '^([0-9A-Z]{3,5})T(\d+)' -and $Matches[1] -eq $instPrefix) {
                    return [math]::Sign($instBuild - [int]$Matches[2])
                }
            }
            return $null
        }
    }
    return $null
}

function ConvertTo-CEUtcDateTime {
    <#
        ISO 8601 timestamp to UTC. pwsh 7's ConvertFrom-Json already turns these into
        DateTime objects, and casting those back to a string loses the UTC marker.
    #>
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    try {
        return [datetime]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal)
    }
    catch { return $null }
}

function ConvertTo-CEDateOnly {
    <# 'yyyy-MM-dd' (or a DateTime, if JSON parsing already converted it) to a date. #>
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    if ($Value -is [datetime]) { return $Value.Date }
    try { return [datetime]::ParseExact([string]$Value, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture) } catch { return $null }
}

function Invoke-CEHttpGet {
    <# Small GET wrapper (Windows PowerShell 5.1 and pwsh) that reports status codes instead of throwing. #>
    param([Parameter(Mandatory)][string]$Uri, [string]$ETag, [int]$TimeoutSeconds = 20)
    Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }
    $client = New-Object System.Net.Http.HttpClient
    try {
        $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
        $request = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Get, $Uri)
        [void]$request.Headers.TryAddWithoutValidation('User-Agent', "EngramicBaseline/$(Get-CEToolVersion)")
        if ($ETag) { [void]$request.Headers.TryAddWithoutValidation('If-None-Match', $ETag) }
        $response = $client.SendAsync($request).GetAwaiter().GetResult()
        $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        $tag = if ($response.Headers.ETag) { $response.Headers.ETag.ToString() } else { '' }
        return [pscustomobject]@{ StatusCode = [int]$response.StatusCode; Body = $body; ETag = $tag }
    }
    finally {
        $client.Dispose()
    }
}

function Test-CEFirmwareCatalogRecord {
    param($Record, [string]$Vendor, [string]$Id)
    if ($null -eq $Record) { return $false }
    if ([int](Get-CEObjectValue $Record 'schemaVersion' 0) -ne 1) { return $false }
    if ([string](Get-CEObjectValue $Record 'vendor' '') -ne $Vendor -or [string](Get-CEObjectValue $Record 'id' '') -ne $Id) { return $false }
    $releases = @(Get-CEObjectValue $Record 'releases' @())
    if ($releases.Count -eq 0) { return $false }
    # Every release must carry a version: SU-08 reads them all, not only the first.
    foreach ($r in $releases) { if (-not (Get-CEObjectValue $r 'version')) { return $false } }
    return ($null -ne (ConvertTo-CEUtcDateTime (Get-CEObjectValue $Record 'checkedAt')))
}

function Get-CEFirmwareCatalogRecord {
    <#
        Returns Status (Found, NotFound, Disabled, Unsupported, Error), Record,
        FromCache and Message. Never throws.
    #>
    [CmdletBinding()]
    param($Hardware)
    $result = [pscustomobject]@{ Status = 'Disabled'; Record = $null; FromCache = $false; Message = ''; Key = $null }
    $cfg = (Get-CEConfig).'firmware-catalog'
    $base = [string](Get-CEObjectValue $cfg 'baseUrl' '')
    if (-not $base.Trim()) { $result.Message = 'Firmware catalog not configured (config/firmware-catalog.json baseUrl)'; return $result }

    $key = Get-CEFirmwareCatalogKey $Hardware
    if (-not $key) {
        $result.Status = 'Unsupported'
        $result.Message = "No firmware catalog for $(Get-CEObjectValue $Hardware 'Manufacturer' 'this manufacturer')"
        return $result
    }
    $result.Key = $key

    $uri = $null
    $vendorSeg = [Uri]::EscapeDataString([string]$key.Vendor)
    $idSeg = [Uri]::EscapeDataString([string]$key.Id)
    try { $uri = [Uri]("$($base.TrimEnd('/'))/v1/firmware/$vendorSeg/$idSeg") } catch { $uri = $null }
    $local = $uri -and @('localhost', '127.0.0.1', '::1', '[::1]') -contains $uri.Host
    if (-not $uri -or -not ($uri.Scheme -eq 'https' -or ($uri.Scheme -eq 'http' -and $local))) {
        $result.Status = 'Error'
        $result.Message = "Firmware catalog baseUrl must be https (http only for localhost): $base"
        return $result
    }

    $cacheDir = Join-Path (Get-CEDataRoot) 'cache'
    $cacheFile = Join-Path $cacheDir "firmware-$($key.Vendor)-$($key.Id).json"
    $cached = $null
    $cachedEtag = ''
    $cacheAgeHours = [double]::MaxValue
    # Don't trust a cached record an elevated audit could have had planted (a forged
    # "up to date" record would suppress SU-08). Skip reading; a fresh fetch still runs.
    $cacheTrusted = (-not (Test-Path -LiteralPath $cacheDir)) -or (Test-CEDataPathTrusted -Path $cacheDir)
    if ($cacheTrusted -and (Test-Path -LiteralPath $cacheFile)) {
        try {
            $wrapper = Get-Content -LiteralPath $cacheFile -Raw | ConvertFrom-Json
            if (Test-CEFirmwareCatalogRecord $wrapper.record $key.Vendor $key.Id) {
                $cached = $wrapper.record
                $cachedEtag = [string]$wrapper.etag
                $fetchedAt = ConvertTo-CEUtcDateTime $wrapper.fetchedAt
                if ($fetchedAt) { $cacheAgeHours = ((Get-Date).ToUniversalTime() - $fetchedAt).TotalHours }
            }
        }
        catch { $cached = $null }
    }
    $useCache = {
        param($why)
        $result.Status = 'Found'; $result.Record = $cached; $result.FromCache = $true; $result.Message = $why
        return $result
    }
    if ($cached -and $cacheAgeHours -lt [double](Get-CEObjectValue $cfg 'cacheHours' 12)) { return (& $useCache 'Cached answer from the firmware catalog') }

    $save = {
        param($record, $etag)
        try {
            if (-not (Test-Path -LiteralPath $cacheDir)) { New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null }
            [pscustomobject]@{ fetchedAt = (Get-Date).ToUniversalTime().ToString('o'); etag = $etag; record = $record } |
                ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $cacheFile -Encoding UTF8
        }
        catch { Write-Verbose "Could not cache firmware catalog record: $_" }
    }

    try {
        $response = Invoke-CEHttpGet -Uri $uri.AbsoluteUri -ETag $cachedEtag -TimeoutSeconds ([int](Get-CEObjectValue $cfg 'timeoutSeconds' 20))
    }
    catch {
        # HttpClient wraps the useful message (e.g. 'No such host is known') in inner exceptions.
        $inner = $_.Exception
        while ($inner.InnerException) { $inner = $inner.InnerException }
        $msg = "Firmware catalog unreachable: $($inner.Message)"
        if ($cached) { return (& $useCache $msg) }
        $result.Status = 'Error'; $result.Message = $msg
        return $result
    }

    switch ($response.StatusCode) {
        200 {
            $record = $null
            try { $record = $response.Body | ConvertFrom-Json } catch { $record = $null }
            if (-not (Test-CEFirmwareCatalogRecord $record $key.Vendor $key.Id)) {
                $msg = 'Firmware catalog returned an invalid record'
                if ($cached) { return (& $useCache $msg) }
                $result.Status = 'Error'; $result.Message = $msg
                return $result
            }
            & $save $record $response.ETag
            $result.Status = 'Found'; $result.Record = $record; $result.Message = 'Firmware catalog answered'
            return $result
        }
        304 {
            & $save $cached $cachedEtag
            return (& $useCache 'Firmware catalog confirmed the cached answer')
        }
        404 {
            $result.Status = 'NotFound'; $result.Message = "The firmware catalog has no entry for $($key.Vendor) $($key.Id)"
            return $result
        }
        default {
            $msg = "Firmware catalog returned HTTP $($response.StatusCode)"
            if ($cached) { return (& $useCache $msg) }
            $result.Status = 'Error'; $result.Message = $msg
            return $result
        }
    }
}
