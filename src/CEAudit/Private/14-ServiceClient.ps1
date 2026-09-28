# ---------------------------------------------------------------------------
# HTTPS client for the tool's own services (the firmware catalog).
# One place for the https-or-localhost rule, TLS 1.2 on Windows PowerShell 5.1,
# response size limits and proxy settings (config/network.json). Audits often
# run as SYSTEM, which has no per-user proxy settings, so SYSTEM falls back to
# the machine's WinHTTP proxy (netsh winhttp set proxy).
# ---------------------------------------------------------------------------

$script:CELocalHosts = @('localhost', '127.0.0.1', '::1', '[::1]')
$script:CEProxyHint = 'If this device uses a proxy, set proxyUrl in network.json.'

function Resolve-CEServiceUri {
    <#
        Joins a configured base URL and a path. Returns Uri ($null when unusable) and Error.
        Only https is accepted, except plain http to this device (a local development server).
    #>
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$BaseUrl, [Parameter(Mandatory)][string]$Path)
    $result = @{ Uri = $null; Error = '' }
    $base = "$BaseUrl".Trim()
    if (-not $base) { $result.Error = 'No base URL is configured'; return $result }
    $uri = $null
    if (-not [Uri]::TryCreate("$($base.TrimEnd('/'))/$($Path.TrimStart('/'))", [UriKind]::Absolute, [ref]$uri)) {
        $result.Error = "The base URL is not valid: $base"
        return $result
    }
    $local = $script:CELocalHosts -contains $uri.Host
    if (-not ($uri.Scheme -eq 'https' -or ($uri.Scheme -eq 'http' -and $local))) {
        $result.Error = "The base URL must be https (http only for localhost): $base"
        return $result
    }
    $result.Uri = $uri
    return $result
}

function Test-CEIsSystem {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    if (-not (Test-CEIsWindows)) { return $false }
    return [bool][Security.Principal.WindowsIdentity]::GetCurrent().IsSystem
}

function Get-CEWinHttpProxyBlob {
    <# The machine WinHTTP proxy setting (netsh winhttp), raw, from the 64-bit registry. $null when unset. #>
    [CmdletBinding()]
    param()
    $base = $null
    $key = $null
    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
        $key = $base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections')
        if (-not $key) { return $null }
        $value = $key.GetValue('WinHttpSettings')
        if ($value -is [byte[]]) { return ,$value }
        return $null
    }
    catch { return $null }
    finally {
        if ($key) { $key.Dispose() }
        if ($base) { $base.Dispose() }
    }
}

function ConvertFrom-CEWinHttpProxyBlob {
    <#
        Parses WinHttpSettings: DWORD version, DWORD counter, DWORD flags (0x2 = a proxy is set),
        DWORD length + ASCII proxy, DWORD length + ASCII bypass list. Returns Proxy (the raw
        string, e.g. 'proxy:8080' or 'http=a:80;https=b:443') and Bypass (entries), or $null.
    #>
    [CmdletBinding()]
    param([AllowNull()][byte[]]$Blob)
    if ($null -eq $Blob -or $Blob.Length -lt 16) { return $null }
    try {
        $flags = [BitConverter]::ToUInt32($Blob, 8)
        if (($flags -band 2) -eq 0) { return $null }
        $proxyLength = [int][BitConverter]::ToUInt32($Blob, 12)
        if ($proxyLength -le 0 -or 16 + $proxyLength -gt $Blob.Length) { return $null }
        $proxy = [Text.Encoding]::ASCII.GetString($Blob, 16, $proxyLength).Trim([char]0).Trim()
        if (-not $proxy) { return $null }
        $bypass = @()
        $at = 16 + $proxyLength
        if ($at + 4 -le $Blob.Length) {
            $bypassLength = [int][BitConverter]::ToUInt32($Blob, $at)
            if ($bypassLength -gt 0 -and $at + 4 + $bypassLength -le $Blob.Length) {
                $text = [Text.Encoding]::ASCII.GetString($Blob, $at + 4, $bypassLength).Trim([char]0)
                $bypass = @($text -split '[;,\s]+' | Where-Object { $_ })
            }
        }
        return @{ Proxy = $proxy; Bypass = $bypass }
    }
    catch { return $null }
}

function Select-CEWinHttpProxy {
    <#
        The proxy address for a request to a Scheme (http or https) from a WinHTTP proxy string, as
        an absolute http URI, or $null for none. As in WinHTTP, per-scheme entries
        ('http=a:80;https=b:443') apply only to their own scheme, so a scheme with no entry goes direct.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Proxy, [Parameter(Mandatory)][ValidateSet('http', 'https')][string]$Scheme)
    $entries = @($Proxy -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $chosen = $null
    if (@($entries | Where-Object { $_ -match '=' }).Count) {
        $hit = @($entries | Where-Object { $_ -match "^$Scheme=" } | Select-Object -First 1)
        if ($hit.Count) { $chosen = $hit[0].Substring($Scheme.Length + 1) }
    }
    elseif ($entries.Count) { $chosen = $entries[0] }
    if (-not $chosen) { return $null }
    if ($chosen -notmatch '^[a-z0-9+.-]+://') { $chosen = "http://$chosen" }
    $uri = $null
    # Only http proxies: .NET Framework (Windows PowerShell 5.1) can't use a proxy at an https address.
    if ([Uri]::TryCreate($chosen, [UriKind]::Absolute, [ref]$uri) -and $uri.Scheme -eq 'http') { return $uri }
    return $null
}

function Test-CEProxyBypass {
    <# Whether a host is on a WinHTTP bypass list: wildcard entries, and <local> for names without a dot. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$HostName, [AllowEmptyCollection()][string[]]$Bypass = @())
    foreach ($entry in @($Bypass)) {
        $e = ($entry -replace '^[a-z]+://', '').Trim()
        if (-not $e) { continue }
        if ($e -eq '<local>') {
            if ($HostName -notmatch '\.') { return $true }
            continue
        }
        if ($HostName -like $e) { return $true }
    }
    return $false
}

function Get-CEProxySetting {
    <#
        How to reach a URI: Mode 'Proxy' (Address), 'Direct', or 'System' (the platform default).
        A proxyUrl in network.json wins. Otherwise SYSTEM, which has no user proxy settings,
        uses the machine WinHTTP proxy unless useWinHttpProxyWhenSystem is false.
        UseDefaultCredentials says whether the proxy may be sent this account's Windows sign-in
        (for SYSTEM, the computer account). The WinHTTP proxy can only be set by an administrator,
        so it gets them; a proxyUrl only with proxyUseDefaultCredentials, so a config file alone
        can't collect the computer account's authentication.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][Uri]$Uri)
    $cfg = $null
    try { $cfg = (Get-CEConfig).network } catch { $cfg = $null }
    $proxyUrl = "$(Get-CEObjectValue $cfg 'proxyUrl' '')".Trim()
    if ($proxyUrl) {
        $p = $null
        # http only: the proxy address, not the requests, which still use https through it (CONNECT).
        # .NET Framework, which Windows PowerShell 5.1 and so the scheduled audit use, can't use an https proxy.
        if ([Uri]::TryCreate($proxyUrl, [UriKind]::Absolute, [ref]$p) -and $p.Scheme -eq 'http') {
            return @{ Mode = 'Proxy'; Address = $p; Source = 'network.json'; UseDefaultCredentials = ((Get-CEObjectValue $cfg 'proxyUseDefaultCredentials' $false) -eq $true) }
        }
        if ($p -and $p.Scheme -eq 'https') { Write-Warning "Ignoring proxyUrl in network.json: use the proxy's http:// address. Requests to https sites still go through it encrypted, and Windows PowerShell can't use an https:// proxy address." }
        else { Write-Warning 'Ignoring proxyUrl in network.json: it must be an http:// URL.' }
    }
    if ([bool](Get-CEObjectValue $cfg 'useWinHttpProxyWhenSystem' $true) -and (Test-CEIsSystem)) {
        $parsed = ConvertFrom-CEWinHttpProxyBlob -Blob (Get-CEWinHttpProxyBlob)
        if ($parsed) {
            if (Test-CEProxyBypass -HostName $Uri.Host -Bypass $parsed.Bypass) { return @{ Mode = 'Direct'; Address = $null; Source = 'WinHTTP'; UseDefaultCredentials = $false } }
            $scheme = if ($Uri.Scheme -eq 'http') { 'http' } else { 'https' }
            $address = Select-CEWinHttpProxy -Proxy $parsed.Proxy -Scheme $scheme
            if ($address) { return @{ Mode = 'Proxy'; Address = $address; Source = 'WinHTTP'; UseDefaultCredentials = $true } }
            # A WinHTTP proxy set only for other schemes: WinHTTP itself would connect directly.
            return @{ Mode = 'Direct'; Address = $null; Source = 'WinHTTP'; UseDefaultCredentials = $false }
        }
    }
    return @{ Mode = 'System'; Address = $null; Source = ''; UseDefaultCredentials = $false }
}

function Get-CEHttpErrorText {
    <# The innermost message of a failed request (HttpClient wraps the useful one), plus the proxy hint. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][Exception]$Exception)
    $inner = $Exception
    while ($inner.InnerException) { $inner = $inner.InnerException }
    $message = "$($inner.Message)".Trim()
    if (-not $message) { $message = 'The request failed' }
    if ($message -notmatch '[.!?]$') { $message += '.' }
    return "$message $script:CEProxyHint"
}

function New-CEHttpHandler {
    <#
        The HttpClientHandler for a proxy setting from Get-CEProxySetting. The Windows sign-in goes
        only to a proxy whose setting allows it (UseDefaultCredentials), never to the site itself.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Proxy)
    Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue
    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.UseDefaultCredentials = $false
    if ($Proxy['Mode'] -eq 'Proxy') {
        $webProxy = [System.Net.WebProxy]::new([Uri]$Proxy['Address'])
        $webProxy.UseDefaultCredentials = ($Proxy['UseDefaultCredentials'] -eq $true)
        $webProxy.BypassProxyOnLocal = $true
        $handler.Proxy = $webProxy
        $handler.UseProxy = $true
    }
    elseif ($Proxy['Mode'] -eq 'Direct') { $handler.UseProxy = $false }
    return $handler
}

function Invoke-CEHttpRequest {
    <#
        One HTTP GET. Returns StatusCode (0 when no response), Body, ETag and Error. Never throws.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [string]$ETag,
        [ValidateRange(1, 600)][int]$TimeoutSeconds = 20,
        [ValidateRange(1024, 16777216)][int]$MaxBytes = 65536
    )
    $result = @{ StatusCode = 0; Body = ''; ETag = ''; Error = '' }
    $handler = $null
    $client = $null
    $request = $null
    $response = $null
    try {
        if ($PSVersionTable.PSVersion.Major -lt 6) {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        }
        $target = [Uri]$Uri
        $handler = New-CEHttpHandler -Proxy (Get-CEProxySetting -Uri $target)

        $client = [System.Net.Http.HttpClient]::new($handler)
        $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
        $client.MaxResponseContentBufferSize = $MaxBytes
        $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $target)
        [void]$request.Headers.TryAddWithoutValidation('User-Agent', "EngramicBaseline/$(Get-CEToolVersion)")
        if ($ETag) { [void]$request.Headers.TryAddWithoutValidation('If-None-Match', $ETag) }
        $response = $client.SendAsync($request).GetAwaiter().GetResult()
        $result.StatusCode = [int]$response.StatusCode
        if ($response.Headers.ETag) { $result.ETag = $response.Headers.ETag.ToString() }
        if ($response.Content) { $result.Body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult() }
    }
    catch {
        $result.Error = Get-CEHttpErrorText -Exception $_.Exception
    }
    finally {
        if ($response) { $response.Dispose() }
        if ($request) { $request.Dispose() }
        if ($client) { $client.Dispose() }
        elseif ($handler) { $handler.Dispose() }
    }
    return $result
}
