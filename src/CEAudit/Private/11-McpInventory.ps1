# ---------------------------------------------------------------------------
# MCP (Model Context Protocol) inventory for the per-user AI probe.
#
# Reads the MCP client-configuration files declared in config/ai-tools.json
# (mcpConfigs), lists the servers each agent is wired to, and CLASSIFIES the
# credentials found in them - provider, type, storage - without ever recording
# a credential value or anything derived from one.
#
# Decisions (see issue #8):
#  * The machine / SYSTEM audit records presence, path and ACL only; it never
#    opens a config file. Parsing and classification happen only in the user's
#    own session (Invoke-CEUserProbe.ps1), on the user's own files.
#  * No fingerprint or salt here. Matching a credential across runs (drift) is a
#    separate follow-up; this module reads, classifies and discards. Nothing
#    derived from a credential value is persisted.
#  * Classify only: no network calls, no token validation, no scope resolution.
# ---------------------------------------------------------------------------

$script:CEMcpCache = $null

function ConvertFrom-CEJsonc {
    <#
        Parses JSON, tolerating JSONC (line/block comments and trailing commas)
        only when strict parsing fails - so the risky path runs only on files
        that need it. Throws on genuinely malformed input; the caller records
        that as a parse failure rather than letting it abort the probe.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)

    $strictOk = $true
    try { $strict = $Text | ConvertFrom-Json -ErrorAction Stop } catch { $strictOk = $false }
    if ($strictOk) { return $strict }

    # Pass 1: strip // line and /* */ block comments, string- and escape-aware.
    $sb = New-Object System.Text.StringBuilder
    $inStr = $false; $esc = $false; $i = 0; $n = $Text.Length
    while ($i -lt $n) {
        $c = $Text[$i]
        if ($inStr) {
            [void]$sb.Append($c)
            if ($esc) { $esc = $false }
            elseif ($c -eq '\') { $esc = $true }
            elseif ($c -eq '"') { $inStr = $false }
            $i++; continue
        }
        if ($c -eq '"') { $inStr = $true; [void]$sb.Append($c); $i++; continue }
        if ($c -eq '/' -and ($i + 1) -lt $n -and $Text[$i + 1] -eq '/') {
            $i += 2; while ($i -lt $n -and $Text[$i] -ne "`n") { $i++ }; continue
        }
        if ($c -eq '/' -and ($i + 1) -lt $n -and $Text[$i + 1] -eq '*') {
            $i += 2
            while (($i + 1) -lt $n -and -not ($Text[$i] -eq '*' -and $Text[$i + 1] -eq '/')) { $i++ }
            $i += 2; continue
        }
        [void]$sb.Append($c); $i++
    }
    $s = $sb.ToString()

    # Pass 2: drop trailing commas before } or ], also string-aware.
    $out = New-Object System.Text.StringBuilder
    $inStr = $false; $esc = $false; $i = 0; $n = $s.Length
    while ($i -lt $n) {
        $c = $s[$i]
        if ($inStr) {
            [void]$out.Append($c)
            if ($esc) { $esc = $false }
            elseif ($c -eq '\') { $esc = $true }
            elseif ($c -eq '"') { $inStr = $false }
            $i++; continue
        }
        if ($c -eq '"') { $inStr = $true; [void]$out.Append($c); $i++; continue }
        if ($c -eq ',') {
            $j = $i + 1
            while ($j -lt $n -and [char]::IsWhiteSpace($s[$j])) { $j++ }
            if ($j -lt $n -and ($s[$j] -eq '}' -or $s[$j] -eq ']')) { $i++; continue }
        }
        [void]$out.Append($c); $i++
    }
    return ($out.ToString() | ConvertFrom-Json -ErrorAction Stop)
}

function Get-CECredentialPatterns {
    <# Loads config/credential-patterns.json (admin-overridable), with a safe default. #>
    $p = (Get-CEConfig)['credential-patterns']
    if ($p) { return $p }
    return [pscustomobject]@{ prefixes = @(); keyNames = @(); referencePatterns = @('^\$\{') }
}

function Test-CECredentialReference {
    <# True when a value points at a secret held elsewhere (e.g. ${env:X}) rather than the secret itself. #>
    param([string]$Value, $Patterns)
    foreach ($rx in @(Get-CEObjectValue $Patterns 'referencePatterns' @())) {
        if ($Value -match $rx) { return $true }
    }
    return $false
}

function Get-CECredentialClass {
    <#
        Classifies one key/value as a credential, or returns $null if it does
        not look like one. Precision over recall: a value is a credential only
        if its prefix matches a known pattern or its key name matches a known
        credential-ish name. Never returns or stores the value.
    #>
    param([string]$Key, [string]$Value, $Patterns)

    $provider = $null; $type = $null; $isCred = $false
    # Prefix match on the value (case-sensitive; tokens are case-sensitive). Most specific first.
    foreach ($pre in @(Get-CEObjectValue $Patterns 'prefixes' @())) {
        $pat = [string]$pre.pattern
        if ($pat -and $Value.StartsWith($pat, [System.StringComparison]::Ordinal)) {
            $provider = [string]$pre.provider; $type = [string]$pre.type; $isCred = $true; break
        }
    }
    # Key-name heuristic (case-insensitive wildcard) when the prefix did not decide it.
    $upperKey = $Key.ToUpperInvariant()
    if (-not $isCred) {
        foreach ($kn in @(Get-CEObjectValue $Patterns 'keyNames' @())) {
            if ($upperKey -like ([string]$kn.match)) {
                $provider = [string]$kn.provider; $type = [string]$kn.type; $isCred = $true; break
            }
        }
    }
    if (-not $isCred) { return $null }
    if (-not $provider) { $provider = 'unknown' }
    if (-not $type) { $type = 'unknown' }

    $storage = if (Test-CECredentialReference -Value $Value -Patterns $Patterns) { 'env-var-reference' }
    elseif ([string]::IsNullOrWhiteSpace($Value)) { 'unresolved' }
    else { 'plaintext-config' }

    return [ordered]@{ key = $Key; provider = $provider; type = $type; storage = $storage }
}

function Get-CEMcpConfigCatalogue {
    <# The (toolId, profile-relative path, format, root) entries declared in ai-tools.json for Windows. #>
    $out = New-Object System.Collections.ArrayList
    foreach ($t in @(Get-CEObjectValue ((Get-CEConfig)['ai-tools']) 'tools' @())) {
        foreach ($m in @(Get-CEObjectValue (Get-CEAIToolSignal -Tool $t) 'mcpConfigs' @())) {
            [void]$out.Add([pscustomobject]@{
                    ToolId = [string]$t.id
                    RelPath = [string]$m.path
                    Format = [string](Get-CEObjectValue $m 'format' 'json')
                    Root   = [string](Get-CEObjectValue $m 'root' 'mcpServers')
                })
        }
    }
    return , $out.ToArray()
}

function ConvertTo-CEMcpServers {
    <# Extracts normalised server records from one parsed config object. Reads no credential values into output. #>
    param($Config, [string]$Root, [string]$ToolId, [string]$RelPath, [string]$AclIssue, $Patterns, [bool]$AclUnread = $false)

    $records = New-Object System.Collections.ArrayList
    $rootObj = Get-CEObjectValue $Config $Root
    if (-not $rootObj) { return , $records.ToArray() }

    foreach ($prop in $rootObj.PSObject.Properties) {
        $name = [string]$prop.Name
        $srv = $prop.Value
        if ($null -eq $srv) { continue }

        $command = [string](Get-CEObjectValue $srv 'command' '')
        $url = [string](Get-CEObjectValue $srv 'url' '')
        $declared = [string](Get-CEObjectValue $srv 'type' (Get-CEObjectValue $srv 'transport' ''))
        $transport = if ($declared) { $declared.ToLowerInvariant() } elseif ($command) { 'stdio' } elseif ($url) { 'http' } else { 'unknown' }

        $srvArgs = @(Get-CEObjectValue $srv 'args' @())
        # The summary names the package a server runs, and must never carry the secret next to it:
        # "npx -y @scope/server sk-live-..." would otherwise put the token in status.json and the report.
        # Anything the classifier recognises is redacted, as is anything shaped like a bare token
        # (long, and without the separators a package name or a path would have).
        $pkg = @($srvArgs |
            Where-Object { $_ -and -not ([string]$_).StartsWith('-') } |
            Select-Object -First 2 |
            ForEach-Object {
                $a = [string]$_
                if (Get-CECredentialClass -Key '(argument)' -Value $a -Patterns $Patterns) { '(redacted)' }
                elseif ($a.Length -ge 20 -and $a -notmatch '[\\/@.:]') { '(redacted)' }
                else { $a }
            })
        $argsSummary = ($pkg -join ' ')
        # Keep scheme, host and port only. Userinfo is a credential, and a path segment is a common
        # place to put a session token, so neither is recorded.
        $endpoint = ''
        if ($url) {
            $parsed = $null
            if ([Uri]::TryCreate($url, [UriKind]::Absolute, [ref]$parsed)) {
                $endpoint = '{0}://{1}' -f $parsed.Scheme, $parsed.Host
                if (-not $parsed.IsDefaultPort) { $endpoint += ':' + $parsed.Port }
                if ($parsed.AbsolutePath -and $parsed.AbsolutePath -ne '/') { $endpoint += '/...' }
            }
            else { $endpoint = '(unreadable url)' }
        }

        $creds = New-Object System.Collections.ArrayList
        # env block
        $env = Get-CEObjectValue $srv 'env'
        if ($env) {
            foreach ($e in $env.PSObject.Properties) {
                $cls = Get-CECredentialClass -Key ([string]$e.Name) -Value ([string]$e.Value) -Patterns $Patterns
                if ($cls) { [void]$creds.Add($cls) }
            }
        }
        # headers (http/sse) can carry bearer tokens
        $headers = Get-CEObjectValue $srv 'headers'
        if ($headers) {
            foreach ($h in $headers.PSObject.Properties) {
                $cls = Get-CECredentialClass -Key ([string]$h.Name) -Value ([string]$h.Value) -Patterns $Patterns
                if ($cls) { [void]$creds.Add($cls) }
            }
        }
        # argument values that are themselves credential-shaped
        foreach ($a in $srvArgs) {
            $cls = Get-CECredentialClass -Key '(argument)' -Value ([string]$a) -Patterns $Patterns
            if ($cls) { [void]$creds.Add($cls) }
        }

        [void]$records.Add([ordered]@{
                toolId          = $ToolId
                configPath      = $RelPath
                serverName      = $name
                transport       = $transport
                command         = $command
                argsSummary     = $argsSummary
                endpoint        = $endpoint
                credentialCount = @($creds).Count
                credentials     = @($creds)
                configAclIssue  = $AclIssue
                aclUnread       = $AclUnread
            })
    }
    return , $records.ToArray()
}

function Get-CEMcpConfigAcl {
    <#
        The permissions problems of an MCP config at Full, shown by its path relative to the profile
        (Rel), never the absolute path. Unread is true when the permissions could not be read; then
        Issue is '' (not "other users can modify it"), and no error text is kept.
    #>
    param([string]$Full, [string]$Rel)
    $problems = @(Get-CEPathAclProblem -Path $Full)
    $unread = [bool]@($problems | Where-Object { ([string]$_).StartsWith("$Full permissions could not be read", [StringComparison]::OrdinalIgnoreCase) }).Count
    if ($unread) { return [pscustomobject]@{ Issue = ''; Unread = $true } }
    $issue = (@($problems | ForEach-Object { ([string]$_).Replace($Full, $Rel) }) -join '; ')
    return [pscustomobject]@{ Issue = $issue; Unread = $false }
}

function Get-CEMcpInventory {
    <#
        Per-user MCP inventory. In a machine / SYSTEM context, records presence,
        path and ACL only (never opens a file). Otherwise parses each config and
        classifies its credentials, storing nothing derived from a credential value.
        Configs are found and read through the profile read layer (15-ProfileReads.ps1).
        mcpConfigsUnreadable lists what could not be read, never dropped: a config
        found and not read (kind file-content: the file is a link, a junction is on
        the way, it is stored online only, too large, unreadable or not parseable),
        a config whose existence could not be checked (kind existence: a symbolic
        link on the way, or a folder or file the audit may not look at, which is not
        counted as found), and a missing or non-local
        profile. Reasons are fixed strings, so no error text (which can quote a
        credential) is ever recorded.
    #>
    [CmdletBinding()]
    param($Context)
    if (-not $Context) { $Context = Get-CEDeviceContext }

    $cacheKey = "$($Context.ComputerName)|$($Context.AuditTime.Ticks)|$($Context.IsElevated)|$($Context.IsSystem)"
    if ($script:CEMcpCache -and $script:CEMcpCache.Key -eq $cacheKey) { return $script:CEMcpCache.Value }

    $servers = New-Object System.Collections.ArrayList
    $log = New-CENotReadLog
    $meta = @{}
    $parsed = 0
    $found = 0
    $patterns = Get-CECredentialPatterns
    $profilePath = Get-CEUserProfilePath -Context $Context
    $machineContext = [bool]$Context.IsSystem
    $above = Test-CEAboveUserRights -Context $Context

    if (-not $profilePath) {
        Add-CENotRead -Log $log -Location '%USERPROFILE%' -Kind 'existence' -Reason $script:CENotReadText.NoProfile -Topic 'profile' `
            -Remedy 'Run the audit while the person who uses this device is signed in at the console.'
    }
    elseif (-not (Test-CEProfileReady $profilePath)) {
        # One record for the profile, not one per catalog entry.
        Add-CENotRead -Log $log -Location '%USERPROFILE%' -Kind 'folder-listing' -Reason $script:CENotReadText.NotLocal -Topic 'mcp' `
            -Remedy 'Check the MCP client configs in this profile by hand.'
    }
    else {
        foreach ($entry in (Get-CEMcpConfigCatalogue)) {
            if (-not $entry.RelPath) { continue }
            $rel = [string]$entry.RelPath
            $loc = Get-CEProfileLocation $rel
            $meta[$loc] = @{ path = $rel; toolId = [string]$entry.ToolId }
            if (-not (Test-CERelativePathText $rel)) {
                Add-CENotRead -Log $log -Location $loc -Kind 'existence' -Reason $script:CENotReadText.Malformed -Topic 'mcp' -Remedy 'Fix the mcpConfigs path in ai-tools.json.'
                continue
            }
            $full = [IO.Path]::Combine($profilePath, $rel)
            $parent = Split-Path -Parent $rel
            # Existence, as for a listing: a symbolic link on the way leaves it unknown (not counted as found);
            # a junction that passes the check lets it be seen, but its contents are never read through it.
            $viaJunction = $false
            if ($parent) {
                $why = Get-CEPathChainProblem -Base $profilePath -Relative $parent -Mode Listing -Log $log -Above $above
                if ($why -eq 'missing') { continue }
                if ($why) { Add-CEWayNotRead -Log $log -Location $loc -Kind 'existence' -Reason $why -Topic 'mcp'; continue }
                $viaJunction = ($above -and (Get-CEPathChainProblem -Base $profilePath -Relative $parent -Mode Content -Log $log -Above $above) -ne '')
            }
            # Only what Windows says is not there is missing; a config the audit may not look at is recorded, not counted.
            $fi = Get-CEItemPresence -Path $full
            if ($fi.State -eq 'missing' -or ($fi.State -eq 'present' -and $fi.IsFolder)) { continue }
            if ($fi.State -ne 'present') { Add-CEWayNotRead -Log $log -Location $loc -Kind 'existence' -Reason $fi.Reason -Topic 'mcp'; continue }
            $found++
            $kind = if ($above) { Get-CEReparseKind -Item $fi } else { 'none' }
            if ($viaJunction -or @('junction', 'symlink', 'surrogate', 'unreadable') -contains $kind) {
                $reason = if ($viaJunction) { $script:CENotReadText.LinkForContent } else { $script:CENotReadText.ItemIsLink }
                Add-CENotRead -Log $log -Location $loc -Kind 'file-content' -Reason $reason -Topic 'mcp' -NeedsUserSession $true
                continue
            }

            if ($machineContext) {
                # Presence, path and ACL only. Do not open the file (a file stored online only is not downloaded either).
                $acl = Get-CEMcpConfigAcl -Full $full -Rel $rel
                [void]$servers.Add([ordered]@{
                        toolId = $entry.ToolId; configPath = $rel; serverName = ''
                        transport = 'not-read'; command = ''; argsSummary = ''; endpoint = ''
                        credentialCount = 0; credentials = @(); configAclIssue = $acl.Issue; aclUnread = $acl.Unread
                    })
                continue
            }

            $raw = Read-CEProfileFile -ProfilePath $profilePath -Relative $rel -MaxBytes 16MB -Log $log -Above $above -Topic 'mcp' `
                -FileRemedy 'Check that the config file can be read, then run the audit again.'
            if ($null -eq $raw) { continue }
            $cfg = $null
            try { $cfg = ConvertFrom-CEJsonc -Text $raw }
            catch {
                # The parser's message can quote the text it choked on, which may be a credential: only its type is kept.
                Write-Verbose "An MCP config for $($entry.ToolId) could not be parsed ($(Get-CEErrorTypeName $_))"
                Add-CENotRead -Log $log -Location $loc -Kind 'file-content' -Reason $script:CENotReadText.Parse -Topic 'mcp' `
                    -Remedy 'Check that each config file named is valid JSON (the audit also accepts comments and trailing commas), then run the audit again.'
                continue
            }
            $parsed++
            $acl = Get-CEMcpConfigAcl -Full $full -Rel $rel
            foreach ($rec in (ConvertTo-CEMcpServers -Config $cfg -Root $entry.Root -ToolId $entry.ToolId -RelPath $rel -AclIssue $acl.Issue -AclUnread $acl.Unread -Patterns $patterns)) {
                [void]$servers.Add($rec)
            }
        }
    }

    $unreadable = @(foreach ($r in (Get-CENotReadRecordArray $log)) {
            $m = if ($meta.ContainsKey($r.Location)) { $meta[$r.Location] } else { @{ path = ''; toolId = '' } }
            [ordered]@{
                path = $m.path; toolId = $m.toolId; reason = $r.Reason; needsUserSession = [bool]$r.NeedsUserSession
                location = $r.Location; kind = $r.Kind; remedy = $r.Remedy; topic = $r.Topic; count = [int]$r.Count
            }
        })
    $allCreds = @(@($servers) | ForEach-Object { @($_.credentials) })
    $bounds = if ($machineContext) { 'machine context: config contents not read; run per-user for parsing' }
    else { 'profile config files only; workspace .mcp.json / WSL configs not scanned' }

    $result = [ordered]@{
        mcpConfigsFound      = $found
        mcpConfigsParsed     = $parsed
        mcpConfigsUnreadable = @($unreadable)
        mcpServers           = @($servers)
        credentialsFound     = @($allCreds).Count
        credentialsPlaintext = @($allCreds | Where-Object { $_.storage -eq 'plaintext-config' }).Count
        scanBounds           = $bounds
    }
    $script:CEMcpCache = @{ Key = $cacheKey; Value = $result }
    return $result
}
