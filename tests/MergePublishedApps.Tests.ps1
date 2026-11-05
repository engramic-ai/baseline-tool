#Requires -Modules Pester
<#
    tools\Merge-PublishedApps.ps1: apps published each to its own folder, merged into one runtime folder.
    The published folders are made up under TestDrive: a .deps.json and .runtimeconfig.json for each app, and
    files whose content says which app wrote them.

    Run:  Invoke-Pester -Path .\tests\MergePublishedApps.Tests.ps1 -Output Detailed
#>

BeforeAll {
    $script:Merge = Join-Path (Join-Path (Split-Path -Parent $PSScriptRoot) 'tools') 'Merge-PublishedApps.ps1'

    function global:New-TestPublish {
        # A published app: <Name>.deps.json, <Name>.runtimeconfig.json naming its frameworks, and the files given,
        # each a relative path and its content.
        param([string]$Path, [string]$Name, [string[]]$Frameworks = @('Microsoft.NETCore.App'), [hashtable]$Files = @{})
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $Path "$Name.deps.json") -Value "{ `"app`": `"$Name`" }" -Encoding ASCII
        $config = @{ runtimeOptions = @{ includedFrameworks = @($Frameworks | ForEach-Object { @{ name = $_; version = '10.0.12' } }) } }
        $config | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $Path "$Name.runtimeconfig.json") -Encoding ASCII
        foreach ($relative in $Files.Keys) {
            $file = Join-Path $Path $relative
            $folder = Split-Path -Parent $file
            if (-not (Test-Path -LiteralPath $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
            [IO.File]::WriteAllText($file, [string]$Files[$relative])
        }
        return $Path
    }

    function global:Set-TestFile {
        # Writes a file, making its folder first.
        param([string]$Path, [string]$Content)
        $folder = Split-Path -Parent $Path
        if (-not (Test-Path -LiteralPath $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
        [IO.File]::WriteAllText($Path, $Content)
    }
}

Describe 'Merge-PublishedApps.ps1' {
    BeforeEach {
        $script:Root = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $script:Cli = New-TestPublish -Path (Join-Path $script:Root 'cli') -Name 'baseline' -Files @{
            'baseline.exe' = 'cli launcher'; 'coreclr.dll' = 'runtime'; 'System.Runtime.dll' = 'runtime'; 'WindowsBase.dll' = 'core facade'
        }
        $script:Desktop = New-TestPublish -Path (Join-Path $script:Root 'desktop') -Name 'BaselineDesktop' -Frameworks @('Microsoft.NETCore.App', 'Microsoft.WindowsDesktop.App') -Files @{
            'BaselineDesktop.exe' = 'desktop launcher'; 'coreclr.dll' = 'runtime'; 'WindowsBase.dll' = 'WPF assembly'; 'System.Diagnostics.EventLog.dll' = 'desktop R2R'
            'de\PresentationCore.resources.dll' = 'German resources'
        }
        $script:Service = New-TestPublish -Path (Join-Path $script:Root 'service') -Name 'BaselineService' -Files @{
            'BaselineService.exe' = 'service launcher'; 'coreclr.dll' = 'runtime'; 'System.Diagnostics.EventLog.dll' = 'package IL'
        }
        $script:Out = Join-Path $script:Root 'runtime'
    }

    It 'copies each file once, keeps every app''s own files and the desktop runtime''s copy of the two files that differ' {
        $rows = @(& $script:Merge -Source $script:Cli, $script:Desktop, $script:Service -Destination $script:Out -PassThru 6>$null)
        $files = @(Get-ChildItem -LiteralPath $script:Out -Recurse -File | ForEach-Object { $_.FullName.Substring($script:Out.Length + 1) } | Sort-Object)
        $files | Should -Be @(
            'baseline.deps.json', 'baseline.exe', 'baseline.runtimeconfig.json',
            'BaselineDesktop.deps.json', 'BaselineDesktop.exe', 'BaselineDesktop.runtimeconfig.json',
            'BaselineService.deps.json', 'BaselineService.exe', 'BaselineService.runtimeconfig.json',
            'coreclr.dll', 'de\PresentationCore.resources.dll', 'System.Diagnostics.EventLog.dll', 'System.Runtime.dll', 'WindowsBase.dll'
        )
        Get-Content -LiteralPath (Join-Path $script:Out 'WindowsBase.dll') -Raw | Should -Be 'WPF assembly'
        Get-Content -LiteralPath (Join-Path $script:Out 'System.Diagnostics.EventLog.dll') -Raw | Should -Be 'desktop R2R'
        ($rows | Where-Object Path -eq 'coreclr.dll').Why | Should -Be 'same content'
        ($rows | Where-Object Path -eq 'coreclr.dll').Apps.Count | Should -Be 3
        ($rows | Where-Object Path -eq 'WindowsBase.dll').Kept | Should -Be 'BaselineDesktop'
    }

    It 'keeps the desktop runtime''s copy whatever order the apps are given in' {
        & $script:Merge -Source $script:Service, $script:Desktop, $script:Cli -Destination $script:Out 6>$null
        Get-Content -LiteralPath (Join-Path $script:Out 'WindowsBase.dll') -Raw | Should -Be 'WPF assembly'
        Get-Content -LiteralPath (Join-Path $script:Out 'System.Diagnostics.EventLog.dll') -Raw | Should -Be 'desktop R2R'
    }

    It 'stops on any other file two apps publish differently, names it, and writes nothing' {
        Set-TestFile -Path (Join-Path $script:Service 'coreclr.dll') -Content 'another runtime'
        Set-TestFile -Path (Join-Path $script:Service 'de\x.dll') -Content 'service'
        Set-TestFile -Path (Join-Path $script:Desktop 'DE\X.dll') -Content 'desktop'
        { & $script:Merge -Source $script:Cli, $script:Desktop, $script:Service -Destination $script:Out 6>$null } |
            Should -Throw -ExpectedMessage '*2 file(s)*coreclr.dll: baseline *BaselineService*'
        Test-Path -LiteralPath $script:Out | Should -BeFalse
    }

    It 'does not let the desktop runtime''s copy win for the two files anywhere but the top of the folder' {
        Set-TestFile -Path (Join-Path $script:Cli 'sub\WindowsBase.dll') -Content 'one'
        Set-TestFile -Path (Join-Path $script:Desktop 'sub\WindowsBase.dll') -Content 'two'
        { & $script:Merge -Source $script:Cli, $script:Desktop -Destination $script:Out 6>$null } | Should -Throw -ExpectedMessage '*sub\WindowsBase.dll*'
    }

    It 'stops when the two files differ between apps and none of them uses the desktop runtime' {
        Set-TestFile -Path (Join-Path $script:Cli 'System.Diagnostics.EventLog.dll') -Content 'cli copy'
        { & $script:Merge -Source $script:Cli, $script:Service -Destination $script:Out 6>$null } | Should -Throw -ExpectedMessage '*System.Diagnostics.EventLog.dll*'
    }

    It 'refuses a destination that holds anything, and leaves it as it was' {
        New-Item -ItemType Directory -Path $script:Out | Out-Null
        Set-TestFile -Path (Join-Path $script:Out 'old.dll') -Content 'old'
        { & $script:Merge -Source $script:Cli -Destination $script:Out 6>$null } | Should -Throw -ExpectedMessage '*not empty*'
        @(Get-ChildItem -LiteralPath $script:Out).Count | Should -Be 1
    }

    It 'refuses a folder that is not one published app, and the same app twice' {
        $plain = Join-Path $script:Root 'plain'
        New-Item -ItemType Directory -Path $plain | Out-Null
        { & $script:Merge -Source $plain -Destination $script:Out 6>$null } | Should -Throw -ExpectedMessage '*0 .deps.json*'
        Remove-Item -LiteralPath (Join-Path $script:Cli 'baseline.runtimeconfig.json')
        { & $script:Merge -Source $script:Cli -Destination $script:Out 6>$null } | Should -Throw -ExpectedMessage '*no baseline.runtimeconfig.json*'
        $again = New-TestPublish -Path (Join-Path $script:Root 'again') -Name 'BaselineService'
        { & $script:Merge -Source $script:Service, $again -Destination $script:Out 6>$null } | Should -Throw -ExpectedMessage '*same app*'
        { & $script:Merge -Source (Join-Path $script:Root 'nowhere') -Destination $script:Out 6>$null } | Should -Throw -ExpectedMessage '*no folder*'
    }

    It 'refuses two apps that use the desktop runtime, as whose copy to keep is then not clear' {
        $other = New-TestPublish -Path (Join-Path $script:Root 'other') -Name 'OtherDesktop' -Frameworks @('Microsoft.NETCore.App', 'Microsoft.WindowsDesktop.App')
        { & $script:Merge -Source $script:Desktop, $other -Destination $script:Out 6>$null } | Should -Throw -ExpectedMessage '*More than one source*'
    }

    It 'refuses a source that holds a link' -Skip:(-not ($PSVersionTable.PSEdition -eq 'Desktop' -or $IsWindows)) {
        $target = Join-Path $script:Root 'elsewhere'
        New-Item -ItemType Directory -Path $target | Out-Null
        # A junction needs no privilege, unlike a symbolic link.
        New-Item -ItemType Junction -Path (Join-Path $script:Cli 'linked') -Target $target | Out-Null
        { & $script:Merge -Source $script:Cli -Destination $script:Out 6>$null } | Should -Throw -ExpectedMessage '*holds a link*'
    }
}
