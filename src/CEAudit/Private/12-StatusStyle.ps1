# ---------------------------------------------------------------------------
# Single source of truth for how a status, severity or framework bucket is
# presented - label, colour (light and dark), and an icon codepoint. Both the
# HTML report and the WPF app read from here so the two surfaces speak one
# vocabulary, use one colour, and show one icon everywhere.
#
# Icons are stored as integer codepoints (source stays ASCII): the report emits
# them as HTML numeric entities ("&#" + code + ";"), the app as [char]$code.
# ---------------------------------------------------------------------------

function Get-CEStatusStyle {
    <#
        Control-status metadata for individual check results (Pass/Fail/Warn/
        Manual/Info/NotApplicable/Skipped/Error). Pass a status for one entry,
        or nothing for the whole ordered map.
    #>
    param([string]$Status)
    $map = [ordered]@{
        Pass          = @{ Label = 'Pass';           Light = '#008687'; Dark = '#35b8b5'; Icon = 0x2713 }
        Fail          = @{ Label = 'Fail';           Light = '#c23f2c'; Dark = '#e88a7c'; Icon = 0x2715 }
        Warn          = @{ Label = 'Warn';           Light = '#a9721a'; Dark = '#dcac57'; Icon = 0x25B2 }
        Manual        = @{ Label = 'Manual';         Light = '#3d6aa0'; Dark = '#8fb2e0'; Icon = 0x25CB }
        Info          = @{ Label = 'Info';           Light = '#3d6aa0'; Dark = '#8fb2e0'; Icon = 0x2139 }
        NotApplicable = @{ Label = 'Not applicable'; Light = '#7d8783'; Dark = '#8b958f'; Icon = 0x2013 }
        Skipped       = @{ Label = 'Skipped';        Light = '#7d8783'; Dark = '#8b958f'; Icon = 0x203A }
        Error         = @{ Label = 'Error';          Light = '#c23f2c'; Dark = '#e88a7c'; Icon = 0x26A0 }
    }
    if ($Status) {
        if ($map.Contains([string]$Status)) { return $map[[string]$Status] }
        return @{ Label = [string]$Status; Light = '#7d8783'; Dark = '#8b958f'; Icon = 0x2013 }
    }
    return $map
}

function Get-CESeverityStyle {
    <# Severity colours (Critical/High/Medium/Low) - the triage dimension, coloured everywhere. #>
    param([string]$Severity)
    $map = [ordered]@{
        Critical = @{ Label = 'Critical'; Light = '#c23f2c'; Dark = '#e88a7c' }
        High     = @{ Label = 'High';     Light = '#d9662b'; Dark = '#e8a06a' }
        Medium   = @{ Label = 'Medium';   Light = '#a9721a'; Dark = '#dcac57' }
        Low      = @{ Label = 'Low';      Light = '#566360'; Dark = '#9aa4a0' }
    }
    if ($Severity) {
        if ($map.Contains([string]$Severity)) { return $map[[string]$Severity] }
        return @{ Label = [string]$Severity; Light = '#566360'; Dark = '#9aa4a0' }
    }
    return $map
}

function Get-CEBucketStyle {
    <# Framework-coverage buckets (rollup only): the reframe's judgement language, one vocabulary on both surfaces. #>
    param([string]$Bucket)
    $map = [ordered]@{
        met       = @{ Label = 'Met';        Light = '#008687'; Dark = '#35b8b5' }
        attention = @{ Label = 'Attention';  Light = '#c23f2c'; Dark = '#e88a7c' }
        confirm   = @{ Label = 'To confirm'; Light = '#3d6aa0'; Dark = '#8fb2e0' }
        na        = @{ Label = 'N/A';        Light = '#7d8783'; Dark = '#8b958f' }
    }
    if ($Bucket) {
        if ($map.Contains([string]$Bucket)) { return $map[[string]$Bucket] }
        return @{ Label = [string]$Bucket; Light = '#7d8783'; Dark = '#8b958f' }
    }
    return $map
}
