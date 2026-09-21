#Requires -Version 5.1
<#
.SYNOPSIS
    Desktop app for the Cyber Essentials checker (WPF, no extra installs).

.DESCRIPTION
    Run the audit, review findings and CE+ readiness, pick fixes, preview and
    apply them, and roll changes back - all from one window. Uses the same
    module as the command-line scripts. Long-running work happens on a
    background runspace so the window stays responsive.

    Easiest way to start: double-click "CE-Checker.cmd".

.PARAMETER OutputRoot
    Where results are stored. Default: .\output next to this script.
#>
[CmdletBinding()]
param(
    [string]$OutputRoot
)

$ErrorActionPreference = 'Stop'
$isWin = ($PSVersionTable.PSVersion.Major -lt 6) -or $IsWindows
if (-not $isWin) { throw 'The Engramic Baseline app runs on Windows only.' }

# WPF needs a single-threaded apartment. Relaunch in Windows PowerShell if needed.
if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    $winPs = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $relaunch = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-File', "`"$PSCommandPath`"")
    if ($OutputRoot) { $relaunch += @('-OutputRoot', "`"$OutputRoot`"") }
    Start-Process -FilePath $winPs -ArgumentList $relaunch
    return
}

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

$script:ModulePath = Join-Path $PSScriptRoot '..\src\CEAudit\CEAudit.psd1'
Import-Module $script:ModulePath -Force
if (-not $OutputRoot) {
    # Next to the scripts when run from a cloned repo; per-user folder when
    # installed under Program Files (not writable by standard users).
    $OutputRoot = Join-Path $PSScriptRoot '..\output'
    try {
        # Installed copies are replaced on upgrade, so never keep results there.
        if ($env:ProgramFiles -and $PSScriptRoot.StartsWith($env:ProgramFiles, [StringComparison]::OrdinalIgnoreCase)) { throw 'installed copy' }
        if (-not (Test-Path -LiteralPath $OutputRoot)) { New-Item -ItemType Directory -Path $OutputRoot -ErrorAction Stop | Out-Null }
        $probe = Join-Path $OutputRoot ('.write-test-' + [guid]::NewGuid().ToString('N'))
        [IO.File]::WriteAllText($probe, 'x')
        Remove-Item -LiteralPath $probe -Force
    }
    catch {
        $OutputRoot = Join-Path $env:LOCALAPPDATA 'EngramicBaseline\output'
    }
}
$script:OutputRoot = $OutputRoot

# ---------------------------------------------------------------------------
# Layout
# ---------------------------------------------------------------------------
[xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Engramic Baseline" Width="1240" Height="820" MinWidth="960" MinHeight="600"
        WindowStartupLocation="CenterScreen" Background="#F2F4F4" FontFamily="Geist, Segoe UI" FontSize="13">
  <Window.Resources>
    <SolidColorBrush x:Key="Ink" Color="#0B0F0E"/>
    <SolidColorBrush x:Key="Muted" Color="#566360"/>
    <SolidColorBrush x:Key="Line" Color="#E2E8E6"/>
    <SolidColorBrush x:Key="Accent" Color="#008687"/>

    <Style TargetType="Button">
      <Setter Property="Padding" Value="14,7"/>
      <Setter Property="Margin" Value="0,0,8,0"/>
      <Setter Property="Background" Value="White"/>
      <Setter Property="BorderBrush" Value="#CBD3D0"/>
      <Setter Property="Foreground" Value="{StaticResource Ink}"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="B" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="1" CornerRadius="6" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="B" Property="Opacity" Value="0.88"/></Trigger>
              <Trigger Property="IsEnabled" Value="False"><Setter TargetName="B" Property="Opacity" Value="0.45"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="Primary" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
      <Setter Property="Background" Value="#0B0F0E"/>
      <Setter Property="BorderBrush" Value="#0B0F0E"/>
      <Setter Property="Foreground" Value="White"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
    </Style>
    <Style x:Key="Danger" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
      <Setter Property="Foreground" Value="#C23F2C"/>
      <Setter Property="BorderBrush" Value="#E7B4AF"/>
    </Style>
    <Style x:Key="H2" TargetType="TextBlock">
      <Setter Property="FontSize" Value="15"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Margin" Value="0,18,0,8"/>
      <Setter Property="Foreground" Value="{StaticResource Ink}"/>
    </Style>
    <Style x:Key="Label" TargetType="TextBlock">
      <Setter Property="Foreground" Value="{StaticResource Muted}"/>
      <Setter Property="FontSize" Value="11"/>
      <Setter Property="Margin" Value="0,10,0,2"/>
    </Style>
    <Style TargetType="DataGrid">
      <Setter Property="AutoGenerateColumns" Value="False"/>
      <Setter Property="IsReadOnly" Value="True"/>
      <Setter Property="CanUserAddRows" Value="False"/>
      <Setter Property="CanUserDeleteRows" Value="False"/>
      <Setter Property="SelectionMode" Value="Single"/>
      <Setter Property="HeadersVisibility" Value="Column"/>
      <Setter Property="GridLinesVisibility" Value="Horizontal"/>
      <Setter Property="HorizontalGridLinesBrush" Value="#E2E8E6"/>
      <Setter Property="Background" Value="White"/>
      <Setter Property="RowBackground" Value="White"/>
      <Setter Property="BorderBrush" Value="{StaticResource Line}"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="RowHeaderWidth" Value="0"/>
      <Setter Property="MinRowHeight" Value="30"/>
    </Style>
    <Style TargetType="DataGridColumnHeader">
      <Setter Property="Background" Value="#F6F8F8"/>
      <Setter Property="Foreground" Value="{StaticResource Muted}"/>
      <Setter Property="FontSize" Value="11"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Padding" Value="8,7"/>
      <Setter Property="BorderBrush" Value="{StaticResource Line}"/>
      <Setter Property="BorderThickness" Value="0,0,0,1"/>
    </Style>
    <Style TargetType="DataGridCell">
      <Setter Property="Padding" Value="8,4"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="VerticalContentAlignment" Value="Center"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="DataGridCell">
            <Border Background="{TemplateBinding Background}" Padding="{TemplateBinding Padding}">
              <ContentPresenter VerticalAlignment="Center"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
      <Style.Triggers>
        <Trigger Property="IsSelected" Value="True">
          <Setter Property="Background" Value="#DCECEC"/>
          <Setter Property="Foreground" Value="{StaticResource Ink}"/>
        </Trigger>
      </Style.Triggers>
    </Style>
    <Style x:Key="Wrap" TargetType="TextBlock">
      <Setter Property="TextWrapping" Value="Wrap"/>
    </Style>

    <!-- Tabs are a flat underline rail. The stock templates draw their own boxes and
         backgrounds whatever properties are set, so both templates are replaced. -->
    <Style TargetType="TabControl">
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Padding" Value="0"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TabControl">
            <Grid>
              <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
              <Border BorderBrush="{StaticResource Line}" BorderThickness="0,0,0,1">
                <TabPanel IsItemsHost="True" Margin="0,0,0,-1"/>
              </Border>
              <ContentPresenter Grid.Row="1" ContentSource="SelectedContent" Margin="0,10,0,0"/>
            </Grid>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <!-- Colour and weight live on the header label (TabLabel), not on the TabItem: anything set on
         the TabItem is inherited by the page content and would embolden every tab body. -->
    <Style TargetType="TabItem">
      <Setter Property="Padding" Value="12,8,12,9"/>
      <Setter Property="Margin" Value="0,0,2,0"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TabItem">
            <Border x:Name="B" Background="Transparent" BorderBrush="Transparent" BorderThickness="0,0,0,2" Padding="{TemplateBinding Padding}">
              <ContentPresenter ContentSource="Header" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsSelected" Value="True">
                <Setter TargetName="B" Property="BorderBrush" Value="{StaticResource Accent}"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="TabLabel" TargetType="TextBlock">
      <Setter Property="Foreground" Value="{StaticResource Muted}"/>
      <Setter Property="FontWeight" Value="Medium"/>
      <Style.Triggers>
        <DataTrigger Binding="{Binding IsMouseOver, RelativeSource={RelativeSource AncestorType=TabItem}}" Value="True">
          <Setter Property="Foreground" Value="{StaticResource Ink}"/>
        </DataTrigger>
        <DataTrigger Binding="{Binding IsSelected, RelativeSource={RelativeSource AncestorType=TabItem}}" Value="True">
          <Setter Property="Foreground" Value="{StaticResource Ink}"/>
          <Setter Property="FontWeight" Value="SemiBold"/>
        </DataTrigger>
        <DataTrigger Binding="{Binding IsEnabled, RelativeSource={RelativeSource AncestorType=TabItem}}" Value="False">
          <Setter Property="Foreground" Value="#AAB3B0"/>
        </DataTrigger>
      </Style.Triggers>
    </Style>
    <!-- Count beside a tab label: mono, teal when that tab is selected -->
    <Style x:Key="TabCount" TargetType="TextBlock">
      <Setter Property="FontSize" Value="11.5"/>
      <Setter Property="FontWeight" Value="Normal"/>
      <Setter Property="Margin" Value="5,0,0,0"/>
      <Setter Property="Foreground" Value="{StaticResource Muted}"/>
      <Style.Triggers>
        <DataTrigger Binding="{Binding IsSelected, RelativeSource={RelativeSource AncestorType=TabItem}}" Value="True">
          <Setter Property="Foreground" Value="#006D6E"/>
        </DataTrigger>
      </Style.Triggers>
    </Style>
    <!-- In-text actions (banner links) -->
    <Style TargetType="Hyperlink">
      <Setter Property="Foreground" Value="#006D6E"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="TextDecorations" Value="{x:Null}"/>
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True"><Setter Property="TextDecorations" Value="Underline"/></Trigger>
      </Style.Triggers>
    </Style>

    <!-- Status pill used by several grids: binds to a column called Status -->
    <DataTemplate x:Key="StatusPill">
      <Border x:Name="Pill" CornerRadius="10" Padding="9,2" HorizontalAlignment="Left" Background="#ECEFED">
        <TextBlock x:Name="PillText" Text="{Binding Status}" FontSize="11" FontWeight="SemiBold" Foreground="#566360"/>
      </Border>
      <DataTemplate.Triggers>
        <DataTrigger Binding="{Binding Status}" Value="Pass"><Setter TargetName="Pill" Property="Background" Value="#DCECEC"/><Setter TargetName="PillText" Property="Foreground" Value="#008687"/></DataTrigger>
        <DataTrigger Binding="{Binding Status}" Value="Likely pass"><Setter TargetName="Pill" Property="Background" Value="#DCECEC"/><Setter TargetName="PillText" Property="Foreground" Value="#008687"/></DataTrigger>
        <DataTrigger Binding="{Binding Status}" Value="Applied"><Setter TargetName="Pill" Property="Background" Value="#DCECEC"/><Setter TargetName="PillText" Property="Foreground" Value="#008687"/></DataTrigger>
        <DataTrigger Binding="{Binding Status}" Value="Fail"><Setter TargetName="Pill" Property="Background" Value="#F8E6E2"/><Setter TargetName="PillText" Property="Foreground" Value="#C23F2C"/></DataTrigger>
        <DataTrigger Binding="{Binding Status}" Value="Likely fail"><Setter TargetName="Pill" Property="Background" Value="#F8E6E2"/><Setter TargetName="PillText" Property="Foreground" Value="#C23F2C"/></DataTrigger>
        <DataTrigger Binding="{Binding Status}" Value="Failed"><Setter TargetName="Pill" Property="Background" Value="#F8E6E2"/><Setter TargetName="PillText" Property="Foreground" Value="#C23F2C"/></DataTrigger>
        <DataTrigger Binding="{Binding Status}" Value="Error"><Setter TargetName="Pill" Property="Background" Value="#F6E6F4"/><Setter TargetName="PillText" Property="Foreground" Value="#8E2A83"/></DataTrigger>
        <DataTrigger Binding="{Binding Status}" Value="Warn"><Setter TargetName="Pill" Property="Background" Value="#F6ECD9"/><Setter TargetName="PillText" Property="Foreground" Value="#A9721A"/></DataTrigger>
        <DataTrigger Binding="{Binding Status}" Value="Check"><Setter TargetName="Pill" Property="Background" Value="#F6ECD9"/><Setter TargetName="PillText" Property="Foreground" Value="#A9721A"/></DataTrigger>
        <DataTrigger Binding="{Binding Status}" Value="Manual"><Setter TargetName="Pill" Property="Background" Value="#E6EEF7"/><Setter TargetName="PillText" Property="Foreground" Value="#3D6AA0"/></DataTrigger>
      </DataTemplate.Triggers>
    </DataTemplate>
    <DataTemplate x:Key="StatePill">
      <StackPanel Orientation="Horizontal">
        <TextBlock x:Name="Mark" Text="" FontSize="10" FontWeight="Bold" Margin="0,0,4,0" VerticalAlignment="Center"/>
        <TextBlock x:Name="StateText" Text="{Binding Status}" FontSize="11.5" FontWeight="SemiBold" Foreground="#566360"/>
      </StackPanel>
      <DataTemplate.Triggers>
        <DataTrigger Binding="{Binding Status}" Value="Pass"><Setter TargetName="StateText" Property="Text" Value="Pass"/><Setter TargetName="StateText" Property="Foreground" Value="#008687"/><Setter TargetName="Mark" Property="Text" Value="&#10003;"/><Setter TargetName="Mark" Property="Foreground" Value="#008687"/></DataTrigger>
        <DataTrigger Binding="{Binding Status}" Value="Fail"><Setter TargetName="StateText" Property="Text" Value="Fail"/><Setter TargetName="StateText" Property="Foreground" Value="#C23F2C"/><Setter TargetName="Mark" Property="Text" Value="&#10005;"/><Setter TargetName="Mark" Property="Foreground" Value="#C23F2C"/></DataTrigger>
        <DataTrigger Binding="{Binding Status}" Value="Warn"><Setter TargetName="StateText" Property="Text" Value="Warn"/><Setter TargetName="StateText" Property="Foreground" Value="#A9721A"/><Setter TargetName="Mark" Property="Text" Value="&#9650;"/><Setter TargetName="Mark" Property="Foreground" Value="#A9721A"/></DataTrigger>
        <DataTrigger Binding="{Binding Status}" Value="Error"><Setter TargetName="StateText" Property="Text" Value="Error"/><Setter TargetName="StateText" Property="Foreground" Value="#C23F2C"/><Setter TargetName="Mark" Property="Text" Value="&#9888;"/><Setter TargetName="Mark" Property="Foreground" Value="#C23F2C"/></DataTrigger>
        <DataTrigger Binding="{Binding Status}" Value="Manual"><Setter TargetName="StateText" Property="Text" Value="Manual"/><Setter TargetName="StateText" Property="Foreground" Value="#3D6AA0"/><Setter TargetName="Mark" Property="Text" Value="&#9675;"/><Setter TargetName="Mark" Property="Foreground" Value="#3D6AA0"/></DataTrigger>
        <DataTrigger Binding="{Binding Status}" Value="Skipped"><Setter TargetName="StateText" Property="Text" Value="Skipped"/><Setter TargetName="StateText" Property="Foreground" Value="#7D8783"/><Setter TargetName="Mark" Property="Text" Value="&#8250;"/><Setter TargetName="Mark" Property="Foreground" Value="#7D8783"/></DataTrigger>
        <DataTrigger Binding="{Binding Status}" Value="NotApplicable"><Setter TargetName="StateText" Property="Text" Value="Not applicable"/><Setter TargetName="StateText" Property="Foreground" Value="#7D8783"/><Setter TargetName="Mark" Property="Text" Value="&#8211;"/><Setter TargetName="Mark" Property="Foreground" Value="#7D8783"/></DataTrigger>
        <DataTrigger Binding="{Binding Status}" Value="Info"><Setter TargetName="StateText" Property="Text" Value="Info"/><Setter TargetName="StateText" Property="Foreground" Value="#3D6AA0"/><Setter TargetName="Mark" Property="Text" Value="&#8505;"/><Setter TargetName="Mark" Property="Foreground" Value="#3D6AA0"/></DataTrigger>
      </DataTemplate.Triggers>
    </DataTemplate>
    <DataTemplate x:Key="AutoFailFlag">
      <TextBlock x:Name="T" Text="" FontSize="11" FontWeight="Bold" Foreground="White"/>
      <DataTemplate.Triggers>
        <DataTrigger Binding="{Binding AutoFail}" Value="True">
          <Setter TargetName="T" Property="Text" Value=" AUTO-FAIL "/>
          <Setter TargetName="T" Property="Background" Value="#C23F2C"/>
        </DataTrigger>
      </DataTemplate.Triggers>
    </DataTemplate>
    <Style x:Key="SevText" TargetType="TextBlock">
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Style.Triggers>
        <DataTrigger Binding="{Binding Severity}" Value="Critical"><Setter Property="Foreground" Value="#C23F2C"/></DataTrigger>
        <DataTrigger Binding="{Binding Severity}" Value="High"><Setter Property="Foreground" Value="#D9662B"/></DataTrigger>
        <DataTrigger Binding="{Binding Severity}" Value="Medium"><Setter Property="Foreground" Value="#A9721A"/></DataTrigger>
        <DataTrigger Binding="{Binding Severity}" Value="Low"><Setter Property="Foreground" Value="#566360"/></DataTrigger>
      </Style.Triggers>
    </Style>
  </Window.Resources>

  <DockPanel>
    <!-- Header -->
    <Border DockPanel.Dock="Top" Background="White" BorderBrush="#008687" BorderThickness="0,0,0,2" Padding="20,14,20,12">
      <Grid>
        <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
        <StackPanel Orientation="Horizontal">
          <Viewbox Width="27" Height="23" Margin="0,0,12,0" VerticalAlignment="Center">
            <Canvas Width="48" Height="44">
              <Path Fill="#0B0F0E" Data="M9,6 L30,6 L39,15 L39,30 L9,30 Z"/>
              <Path Fill="#008687" Data="M2,35 L46,35 L46,42 L2,42 Z"/>
            </Canvas>
          </Viewbox>
          <StackPanel VerticalAlignment="Center">
            <TextBlock Text="ENGRAMIC BASELINE" Foreground="{StaticResource Ink}" FontSize="14" FontWeight="SemiBold"/>
            <TextBlock x:Name="DeviceText" Foreground="{StaticResource Muted}" Margin="0,2,0,0" FontSize="12"/>
          </StackPanel>
        </StackPanel>
        <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center">
          <Border x:Name="ElevBadge" CornerRadius="4" Padding="8,3" Margin="0,0,10,0" VerticalAlignment="Center">
            <TextBlock x:Name="ElevText" FontSize="10.5" FontWeight="SemiBold"/>
          </Border>
          <Button x:Name="RestartAdminBtn" Content="Restart as administrator" Margin="0"/>
        </StackPanel>
      </Grid>
    </Border>

    <!-- Toolbar -->
    <Border DockPanel.Dock="Top" Background="White" BorderBrush="{StaticResource Line}" BorderThickness="0,0,0,1" Padding="20,10">
      <Grid>
        <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
        <WrapPanel VerticalAlignment="Center">
          <Button x:Name="RunBtn" Content="Run audit  &#8594;" Style="{StaticResource Primary}"/>
          <Button x:Name="ChooseChecksBtn" Content="Choose checks..."/>
          <TextBlock x:Name="SelectionText" VerticalAlignment="Center" Foreground="{StaticResource Muted}" Margin="2,0,18,0"/>
          <Button x:Name="OpenReportBtn" Content="Open report" IsEnabled="False"/>
          <Button x:Name="MoreBtn" Content="More  &#9662;">
            <Button.ContextMenu>
              <ContextMenu>
                <MenuItem x:Name="OpenFolderBtn" Header="Open results folder" IsEnabled="False"/>
                <MenuItem x:Name="LoadBtn" Header="Load previous results..."/>
              </ContextMenu>
            </Button.ContextMenu>
          </Button>
        </WrapPanel>
      </Grid>
    </Border>

    <!-- Activity bar: the current task and its progress, expanding into the full log -->
    <Border DockPanel.Dock="Bottom" Background="White" BorderBrush="{StaticResource Line}" BorderThickness="0,1,0,0">
      <StackPanel>
        <Grid x:Name="ActBar" Margin="20,7,20,7" Background="Transparent" Cursor="Hand">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>
          <TextBlock x:Name="ActChevron" Text="&#8964;" FontSize="14" Foreground="{StaticResource Muted}" VerticalAlignment="Center" Margin="0,0,8,0"/>
          <TextBlock Grid.Column="1" Text="ACTIVITY" FontSize="11" FontWeight="SemiBold" Foreground="{StaticResource Ink}" VerticalAlignment="Center" Margin="0,0,12,0"/>
          <TextBlock x:Name="StatusText" Grid.Column="2" Text="Ready" FontSize="12" Foreground="{StaticResource Ink}" VerticalAlignment="Center" TextTrimming="CharacterEllipsis"/>
          <TextBlock x:Name="ActMeta" Grid.Column="3" FontSize="11.5" Foreground="{StaticResource Muted}" VerticalAlignment="Center" Margin="12,0,12,0"/>
          <ProgressBar x:Name="Progress" Grid.Column="4" Width="220" Height="6" Minimum="0" Maximum="100" Value="0" Foreground="#008687" Background="#E2E8E6" BorderThickness="0" VerticalAlignment="Center" Visibility="Collapsed"/>
        </Grid>
        <TextBox x:Name="LogBox" Height="150" IsReadOnly="True" FontFamily="Geist Mono, Consolas" FontSize="12" Margin="20,0,20,10" Visibility="Collapsed"
                 VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto" Background="#F6F8F8" BorderBrush="{StaticResource Line}"/>
      </StackPanel>
    </Border>

    <Grid Margin="20,14,20,10">
      <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
      <Border x:Name="VerdictBanner" Background="White" BorderBrush="#B8C4C0" BorderThickness="6,1,1,1" CornerRadius="6" Padding="18,14,18,13" Margin="0,0,0,14">
        <StackPanel>
          <TextBlock x:Name="VerdictText" FontSize="20" FontWeight="SemiBold" Text="No results yet" TextWrapping="Wrap"/>
          <TextBlock x:Name="VerdictSub" Foreground="{StaticResource Muted}" Margin="0,4,0,0" TextWrapping="Wrap"
                     Text="Checks this device against Cyber Essentials v3.3, the CE+ device tests and NCSC guidance. Reads settings only; nothing changes until you apply fixes."/>
          <Border x:Name="AiLine" BorderBrush="{StaticResource Line}" BorderThickness="0,1,0,0" Margin="0,8,0,0" Padding="0,8,0,0" Visibility="Collapsed">
            <Grid>
              <Grid.ColumnDefinitions><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
              <TextBlock Text="AI" FontSize="11" FontWeight="SemiBold" Foreground="{StaticResource Muted}" VerticalAlignment="Center" Margin="0,0,10,0"/>
              <TextBlock x:Name="AiLineText" Grid.Column="1" VerticalAlignment="Center" TextWrapping="Wrap"/>
              <TextBlock Grid.Column="2" VerticalAlignment="Center" Margin="12,0,0,0"><Hyperlink x:Name="AiTabLink">AI tab &#8594;</Hyperlink></TextBlock>
            </Grid>
          </Border>
        </StackPanel>
      </Border>

      <TabControl x:Name="Tabs" Grid.Row="1" Background="Transparent" BorderThickness="0" Padding="0,10,0,0">
        <!-- Overview -->
        <TabItem Header="Overview">
          <ScrollViewer VerticalScrollBarVisibility="Auto">
            <StackPanel Margin="0,4,8,8">
              <StackPanel x:Name="OvEmpty" Margin="0,30,0,0" MaxWidth="560" HorizontalAlignment="Left">
                <TextBlock x:Name="OvEmptyTitle" FontSize="15" FontWeight="SemiBold" Text="Run an audit to see where this device stands" TextWrapping="Wrap"/>
                <TextBlock x:Name="OvEmptyText" Foreground="{StaticResource Muted}" Margin="0,4,0,0" TextWrapping="Wrap"
                           Text="Frameworks, controls by status and any fixes will appear here. A standard-user run skips checks that need administrator rights."/>
              </StackPanel>
              <StackPanel x:Name="OvBody" Visibility="Collapsed">
              <TextBlock Text="Frameworks" Style="{StaticResource H2}" Margin="0,4,0,8"/>
              <TextBlock Text="% of applicable controls met - target 100%" Foreground="{StaticResource Muted}" FontSize="11.5" Margin="0,0,0,2"/>
              <StackPanel x:Name="FwBars" Margin="0,2,0,10"/>
              <TextBlock Text="Controls by status" Style="{StaticResource H2}"/>
              <Border x:Name="StatusStack" Height="26" BorderBrush="{StaticResource Line}" BorderThickness="1" Margin="0,2,0,6"/>
              <WrapPanel x:Name="StatusLegend" Margin="0,0,0,6"/>
              <TextBlock Margin="0,18,0,0" FontSize="11.5" Foreground="{StaticResource Muted}" TextWrapping="Wrap"
                         Text="Reported as they are - each framework carries its own judgement. Self-assessment aid: it does not replace an IASME-licensed Certification Body and cannot see routers, cloud tenants or other devices in scope."/>
              </StackPanel>
            </StackPanel>
          </ScrollViewer>
        </TabItem>

        <!-- AI -->
        <TabItem Header="AI">
          <ScrollViewer VerticalScrollBarVisibility="Auto">
            <StackPanel Margin="0,4,8,8">
              <Border Background="White" BorderBrush="#008687" BorderThickness="3,1,1,1" CornerRadius="6" Padding="14,10" Margin="0,0,0,10">
                <StackPanel>
                  <TextBlock x:Name="AiSummary" FontSize="15" FontWeight="SemiBold" Text="Run an audit to see AI posture" TextWrapping="Wrap"/>
                  <TextBlock Foreground="{StaticResource Muted}" Margin="0,3,0,0" TextWrapping="Wrap"
                             Text="The agents, WSL distributions and MCP servers you use live in your session. This shows your posture; other users are audited in their own sessions, and SYSTEM never sees shadow AI."/>
                </StackPanel>
              </Border>
              <TextBlock Text="Agents and tools" Style="{StaticResource H2}"/>
              <StackPanel x:Name="AiAgents" Margin="0,2,0,8"/>
              <TextBlock Text="Where AI runs" Style="{StaticResource H2}"/>
              <StackPanel x:Name="AiEnvs" Margin="0,2,0,8"/>
              <TextBlock Text="AI-related controls" Style="{StaticResource H2}"/>
              <DataGrid x:Name="AiControls">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="ID" Binding="{Binding ID}" Width="70"/>
                  <DataGridTemplateColumn Header="STATUS" CellTemplate="{StaticResource StatusPill}" Width="100" SortMemberPath="Status"/>
                  <DataGridTextColumn Header="CONTROL" Binding="{Binding Check}" Width="*" ElementStyle="{StaticResource Wrap}"/>
                </DataGrid.Columns>
              </DataGrid>
            </StackPanel>
          </ScrollViewer>
        </TabItem>

        <!-- Frameworks -->
        <TabItem Header="Frameworks">
          <ScrollViewer VerticalScrollBarVisibility="Auto">
            <StackPanel Margin="0,4,8,8">
              <TextBlock Text="Cyber Essentials Plus readiness (device tests)" Style="{StaticResource H2}"/>
              <DataGrid x:Name="TcGrid">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="TEST" Binding="{Binding Test}" Width="70"/>
                  <DataGridTextColumn Header="NAME" Binding="{Binding Name}" Width="260"/>
                  <DataGridTextColumn Header="WHAT IS TESTED" Binding="{Binding Scope}" Width="*" ElementStyle="{StaticResource Wrap}"/>
                  <DataGridTemplateColumn Header="ESTIMATE" CellTemplate="{StaticResource StatusPill}" Width="120"/>
                </DataGrid.Columns>
              </DataGrid>
              <TextBlock Text="By control theme" Style="{StaticResource H2}"/>
              <DataGrid x:Name="ThemeGrid">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="THEME" Binding="{Binding Theme}" Width="*"/>
                  <DataGridTextColumn Header="PASS" Binding="{Binding Pass}" Width="80"/>
                  <DataGridTextColumn Header="FAIL" Binding="{Binding Fail}" Width="80"/>
                  <DataGridTextColumn Header="WARN" Binding="{Binding Warn}" Width="80"/>
                  <DataGridTextColumn Header="MANUAL" Binding="{Binding Manual}" Width="80"/>
                  <DataGridTextColumn Header="OTHER" Binding="{Binding Other}" Width="80"/>
                </DataGrid.Columns>
              </DataGrid>
              <TextBlock Margin="0,16,0,0" Foreground="{StaticResource Muted}" TextWrapping="Wrap"
                         Text="TC1 (external scan) is run by your assessor against your internet-facing IP addresses."/>
            </StackPanel>
          </ScrollViewer>
        </TabItem>

        <!-- Controls -->
        <TabItem x:Name="FindingsTab" Header="Controls">
          <Grid Margin="0,4,0,0">
            <Grid.RowDefinitions>
              <RowDefinition Height="Auto"/><RowDefinition Height="2*"/><RowDefinition Height="6"/><RowDefinition Height="*" MinHeight="120"/>
            </Grid.RowDefinitions>
            <WrapPanel Margin="0,0,0,8">
              <TextBlock Text="Theme" VerticalAlignment="Center" Margin="0,0,6,0" Foreground="{StaticResource Muted}"/>
              <ComboBox x:Name="ThemeFilter" Width="220" Margin="0,0,16,0"/>
              <TextBlock Text="Status" VerticalAlignment="Center" Margin="0,0,6,0" Foreground="{StaticResource Muted}"/>
              <ComboBox x:Name="StatusFilter" Width="150" Margin="0,0,16,0"/>
              <TextBlock Text="Search" VerticalAlignment="Center" Margin="0,0,6,0" Foreground="{StaticResource Muted}"/>
              <TextBox x:Name="SearchBox" Width="260" Padding="4,3"/>
              <TextBlock x:Name="FindingCount" VerticalAlignment="Center" Margin="16,0,0,0" Foreground="{StaticResource Muted}"/>
            </WrapPanel>
            <DataGrid x:Name="FindingsGrid" Grid.Row="1">
              <DataGrid.Columns>
                <DataGridTextColumn Header="ID" Binding="{Binding CheckId}" Width="70"/>
                <DataGridTemplateColumn Header="STATE" CellTemplate="{StaticResource StatePill}" Width="110" SortMemberPath="Status"/>
                <DataGridTemplateColumn Header="" CellTemplate="{StaticResource AutoFailFlag}" Width="80" SortMemberPath="AutoFail"/>
                <DataGridTextColumn Header="SEVERITY" Binding="{Binding Severity}" Width="80" ElementStyle="{StaticResource SevText}"/>
                <DataGridTextColumn Header="CHECK" Binding="{Binding Title}" Width="2*" ElementStyle="{StaticResource Wrap}"/>
                <DataGridTextColumn Header="RESULT" Binding="{Binding Actual}" Width="3*" ElementStyle="{StaticResource Wrap}"/>
                <DataGridTextColumn Header="FRAMEWORKS" Binding="{Binding Frameworks}" Width="130" ElementStyle="{StaticResource Wrap}"/>
              </DataGrid.Columns>
            </DataGrid>
            <GridSplitter Grid.Row="2" HorizontalAlignment="Stretch" Background="Transparent"/>
            <Border Grid.Row="3" Background="White" BorderBrush="{StaticResource Line}" BorderThickness="1" CornerRadius="6" Padding="14,4,14,12">
              <ScrollViewer VerticalScrollBarVisibility="Auto">
                <StackPanel x:Name="DetailPanel">
                  <TextBlock x:Name="DetTitle" FontSize="15" FontWeight="SemiBold" Margin="0,8,0,0" TextWrapping="Wrap" Text="Select a finding to see details"/>
                  <TextBlock x:Name="DetRef" Foreground="{StaticResource Muted}" TextWrapping="Wrap" Margin="0,2,0,0"/>
                  <TextBlock Text="EXPECTED" Style="{StaticResource Label}"/>
                  <TextBlock x:Name="DetExpected" TextWrapping="Wrap"/>
                  <TextBlock Text="FOUND" Style="{StaticResource Label}"/>
                  <TextBlock x:Name="DetActual" TextWrapping="Wrap"/>
                  <TextBlock Text="WHAT TO DO" Style="{StaticResource Label}"/>
                  <TextBlock x:Name="DetRec" TextWrapping="Wrap"/>
                  <TextBlock x:Name="DetFix" TextWrapping="Wrap" Margin="0,6,0,0" Foreground="#006D6E"/>
                  <TextBlock Text="EVIDENCE" Style="{StaticResource Label}"/>
                  <TextBox x:Name="DetEvidence" IsReadOnly="True" TextWrapping="Wrap" FontFamily="Geist Mono, Consolas" FontSize="12" MaxHeight="220"
                           VerticalScrollBarVisibility="Auto" Background="#F6F8F8" BorderBrush="{StaticResource Line}"/>
                </StackPanel>
              </ScrollViewer>
            </Border>
          </Grid>
        </TabItem>

        <!-- Changeset -->
        <TabItem x:Name="ChangesTab" Header="Fixes">
          <Grid Margin="0,4,0,0">
            <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
            <TextBlock TextWrapping="Wrap" Foreground="{StaticResource Muted}" Margin="0,0,0,10"
                       Text="Tick the fixes to apply. Recommended low and medium risk fixes are pre-ticked; high-risk fixes never are. Preview shows what would change without changing anything. Every applied change is logged so it can be rolled back from the History tab."/>
            <WrapPanel Grid.Row="1" Margin="0,0,0,8">
              <Button x:Name="SelRecBtn" Content="Tick recommended"/>
              <Button x:Name="SelAutoBtn" Content="Tick auto-fail fixes only"/>
              <Button x:Name="SelNoneBtn" Content="Untick all"/>
              <Border Width="18"/>
              <Button x:Name="PreviewBtn" Content="Preview (no changes)"/>
              <Button x:Name="ApplyBtn" Content="Apply ticked fixes" Style="{StaticResource Primary}"/>
              <TextBlock x:Name="SelCount" VerticalAlignment="Center" Margin="10,0,0,0" Foreground="{StaticResource Muted}"/>
            </WrapPanel>
            <DataGrid x:Name="ChangesGrid" Grid.Row="2" IsReadOnly="False">
              <DataGrid.Columns>
                <DataGridTemplateColumn Header="APPLY" Width="60" SortMemberPath="Selected">
                  <DataGridTemplateColumn.CellTemplate>
                    <DataTemplate>
                      <CheckBox IsChecked="{Binding Selected, Mode=TwoWay, UpdateSourceTrigger=PropertyChanged}" HorizontalAlignment="Center"/>
                    </DataTemplate>
                  </DataGridTemplateColumn.CellTemplate>
                </DataGridTemplateColumn>
                <DataGridTextColumn Header="ITEM" Binding="{Binding ItemId}" Width="60" IsReadOnly="True"/>
                <DataGridTextColumn Header="FIX" Binding="{Binding Title}" Width="3*" IsReadOnly="True" ElementStyle="{StaticResource Wrap}"/>
                <DataGridTemplateColumn Header="" CellTemplate="{StaticResource AutoFailFlag}" Width="80" SortMemberPath="AutoFail"/>
                <DataGridTextColumn Header="SEVERITY" Binding="{Binding Severity}" Width="80" ElementStyle="{StaticResource SevText}" IsReadOnly="True"/>
                <DataGridTextColumn Header="RISK" Binding="{Binding Risk}" Width="70" IsReadOnly="True"/>
                <DataGridTextColumn Header="RESTART" Binding="{Binding Reboot}" Width="70" IsReadOnly="True"/>
                <DataGridTextColumn Header="ADMIN" Binding="{Binding Admin}" Width="60" IsReadOnly="True"/>
                <DataGridTextColumn Header="WHY" Binding="{Binding Why}" Width="3*" IsReadOnly="True" ElementStyle="{StaticResource Wrap}"/>
              </DataGrid.Columns>
            </DataGrid>
            <Border Grid.Row="3" Background="White" BorderBrush="{StaticResource Line}" BorderThickness="1" CornerRadius="6" Padding="14,10" Margin="0,8,0,0">
              <TextBlock x:Name="ChangeNotes" TextWrapping="Wrap" Foreground="{StaticResource Muted}" Text="Select a fix to see its notes."/>
            </Border>
          </Grid>
        </TabItem>

        <!-- Manual actions -->
        <TabItem x:Name="ManualTab" Header="Manual actions">
          <Grid Margin="0,4,0,0">
            <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
            <TextBlock TextWrapping="Wrap" Foreground="{StaticResource Muted}" Margin="0,0,0,10"
                       Text="Things a script can't safely do or can't see: attesting MFA on cloud services, reviewing software and firewall rules, turning on Tamper Protection, encrypting the drive. Record what you did for your evidence pack."/>
            <DataGrid x:Name="ManualGrid" Grid.Row="1">
              <DataGrid.Columns>
                <DataGridTemplateColumn Header="STATUS" CellTemplate="{StaticResource StatusPill}" Width="90" SortMemberPath="Status"/>
                <DataGridTemplateColumn Header="" CellTemplate="{StaticResource AutoFailFlag}" Width="80" SortMemberPath="AutoFail"/>
                <DataGridTextColumn Header="SEVERITY" Binding="{Binding Severity}" Width="80" ElementStyle="{StaticResource SevText}"/>
                <DataGridTextColumn Header="ACTION" Binding="{Binding Title}" Width="2*" ElementStyle="{StaticResource Wrap}"/>
                <DataGridTextColumn Header="FOUND" Binding="{Binding Actual}" Width="2*" ElementStyle="{StaticResource Wrap}"/>
                <DataGridTextColumn Header="WHAT TO DO" Binding="{Binding Recommendation}" Width="3*" ElementStyle="{StaticResource Wrap}"/>
              </DataGrid.Columns>
            </DataGrid>
          </Grid>
        </TabItem>

        <!-- History -->
        <TabItem x:Name="HistoryTab" Header="History">
          <Grid Margin="0,4,0,0">
            <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
            <TextBlock TextWrapping="Wrap" Foreground="{StaticResource Muted}" Margin="0,0,0,10"
                       Text="Each time fixes are applied an undo log is saved. Rolling back restores the previous settings in reverse order. Windows and app updates can't be rolled back here."/>
            <WrapPanel Grid.Row="1" Margin="0,0,0,8">
              <Button x:Name="HistRefreshBtn" Content="Refresh"/>
              <Button x:Name="RollbackBtn" Content="Roll back selected" Style="{StaticResource Danger}"/>
              <Button x:Name="HistOpenBtn" Content="Open undo log"/>
            </WrapPanel>
            <DataGrid x:Name="HistoryGrid" Grid.Row="2">
              <DataGrid.Columns>
                <DataGridTextColumn Header="APPLIED" Binding="{Binding AppliedAt}" Width="150"/>
                <DataGridTextColumn Header="BY" Binding="{Binding AppliedBy}" Width="160"/>
                <DataGridTextColumn Header="CHANGES" Binding="{Binding Items}" Width="80"/>
                <DataGridTextColumn Header="SUMMARY" Binding="{Binding Summary}" Width="*" ElementStyle="{StaticResource Wrap}"/>
              </DataGrid.Columns>
            </DataGrid>
            <TextBlock x:Name="HistEmpty" Grid.Row="2" Margin="2,14,0,0" VerticalAlignment="Top" Foreground="{StaticResource Muted}"
                       Visibility="Collapsed" TextWrapping="Wrap"
                       Text="No fixes have been applied on this device yet. When you apply fixes from the Fixes tab, each run is logged here so you can roll it back."/>
          </Grid>
        </TabItem>
      </TabControl>
    </Grid>
  </DockPanel>
</Window>
'@

$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [Windows.Markup.XamlReader]::Load($reader)
$script:IconPath = Join-Path $PSScriptRoot 'engramic-baseline.ico'
function Set-CEWindowIcon($Win) {
    if (Test-Path -LiteralPath $script:IconPath) {
        try { $Win.Icon = New-Object Windows.Media.Imaging.BitmapImage (New-Object System.Uri($script:IconPath)) }
        catch { Write-Verbose "Could not set window icon: $($_.Exception.Message)" }
    }
}
Set-CEWindowIcon $window

# Bundled Geist fonts (OFL). Non-installed fonts must be referenced by folder URI,
# not family name, so wire them in code and fall back to the system stack if absent.
$script:GeistFamily = $null
$script:GeistMonoFamily = $null
$fontDir = Join-Path $PSScriptRoot 'fonts'
if (Test-Path -LiteralPath (Join-Path $fontDir 'Geist.ttf')) {
    try {
        $fontUri = ([Uri]("$fontDir\")).AbsoluteUri
        $script:GeistFamily = New-Object Windows.Media.FontFamily("$fontUri#Geist")
        $script:GeistMonoFamily = New-Object Windows.Media.FontFamily("$fontUri#Geist Mono")
        $window.FontFamily = $script:GeistFamily
    }
    catch { Write-Verbose "Could not load bundled fonts: $($_.Exception.Message)" }
}
function Get-CEMono { if ($script:GeistMonoFamily) { return $script:GeistMonoFamily } else { return (New-Object Windows.Media.FontFamily('Consolas')) } }

$ui = @{}
$xaml.SelectNodes('//*[@*[local-name()="Name"]]') | ForEach-Object {
    $name = $_.Attributes | Where-Object { $_.LocalName -eq 'Name' } | Select-Object -First 1 -ExpandProperty Value
    $ui[$name] = $window.FindName($name)
}
if ($script:GeistMonoFamily) {
    foreach ($n in 'LogBox', 'DetEvidence') { if ($ui[$n]) { $ui[$n].FontFamily = $script:GeistMonoFamily } }
}

$script:Brush = New-Object Windows.Media.BrushConverter
function Get-Brush([string]$Hex) { return $script:Brush.ConvertFromString($Hex) }

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
$script:Current = $null          # @{ Findings; Context; Summary; Changeset; Folder; Paths }
$script:FindingIndex = @{}
$script:ChangeIndex = @{}
$script:Job = $null
$script:Sync = [hashtable]::Synchronized(@{ Current = ''; Done = 0; Total = 0 })
$script:Busy = $false

$statusOrder = @('Pass', 'Fail', 'Warn', 'Manual', 'Skipped', 'NotApplicable', 'Error')
# Includes categories added by installed packs.
$themeLabels = [ordered]@{}
foreach ($category in @(Get-CECategory)) { $themeLabels[$category.Id] = $category.Label }

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-UiLog {
    param([string]$Text)
    $ui.LogBox.AppendText(("[{0}] {1}`r`n" -f (Get-Date -Format 'HH:mm:ss'), $Text))
    $ui.LogBox.ScrollToEnd()
}

function Show-UiMessage {
    param([string]$Text, [string]$Title = 'Engramic Baseline', [string]$Buttons = 'OK', [string]$Icon = 'Information')
    return [Windows.MessageBox]::Show($window, $Text, $Title, $Buttons, $Icon)
}

function Invoke-UiSafe {
    param([scriptblock]$Action)
    try { & $Action }
    catch {
        Write-UiLog "ERROR: $($_.Exception.Message)"
        [void](Show-UiMessage -Text $_.Exception.Message -Icon 'Error')
    }
}

function Set-UiBusy {
    param([bool]$On, [string]$Text = '')
    $script:Busy = $On
    foreach ($n in @('RunBtn', 'ChooseChecksBtn', 'LoadBtn', 'PreviewBtn', 'ApplyBtn', 'RollbackBtn', 'RestartAdminBtn')) { $ui[$n].IsEnabled = -not $On }
    $ui.Progress.IsIndeterminate = $false
    $ui.Progress.Value = 0
    $ui.Progress.Visibility = if ($On) { 'Visible' } else { 'Collapsed' }
    $ui.StatusText.Foreground = Get-Brush $(if ($On) { '#3D6AA0' } else { '#0B0F0E' })
    if ($On) { $ui.StatusText.Text = $Text; $ui.ActMeta.Text = '' }
}

function Set-UiRichText {
    # Fill a TextBlock from parts: @{ Text; Colour; Weight; Link = { ... } }. A part with Link becomes a Hyperlink.
    param($Block, [object[]]$Parts)
    $Block.Inlines.Clear()
    foreach ($p in $Parts) {
        if (-not $p) { continue }
        $run = New-Object Windows.Documents.Run ([string]$p['Text'])
        if ($p['Colour']) { $run.Foreground = Get-Brush $p['Colour'] }
        if ($p['Weight']) { $run.FontWeight = $p['Weight'] }
        if ($p['Link']) {
            $link = New-Object Windows.Documents.Hyperlink $run
            $link.Add_Click($p['Link'])
            [void]$Block.Inlines.Add($link)
        }
        else { [void]$Block.Inlines.Add($run) }
    }
}

function Set-UiVerdict {
    # Headline plus an optional softer second clause: "6 controls need attention - 5 to confirm"
    param([string]$Head, [string]$Soft = '', [string]$Rail = '#B8C4C0')
    $parts = @(@{ Text = $Head })
    if ($Soft) {
        $parts += @{ Text = (' ' + [char]0xB7 + ' '); Colour = '#B6BFBC'; Weight = 'Normal' }
        $parts += @{ Text = $Soft; Colour = '#566360'; Weight = 'Medium' }
    }
    Set-UiRichText -Block $ui.VerdictText -Parts $parts
    $ui.VerdictBanner.BorderBrush = Get-Brush $Rail
}

function Set-UiTabHeader {
    # Tab label with an optional mono count beside it (styled by the TabCount resource).
    param($Tab, [string]$Label, $Count)
    $sp = New-Object Windows.Controls.StackPanel
    $sp.Orientation = 'Horizontal'
    $t = New-Object Windows.Controls.TextBlock
    $t.Style = $window.FindResource('TabLabel')
    $t.Text = $Label; $t.VerticalAlignment = 'Center'
    [void]$sp.Children.Add($t)
    if ($null -ne $Count) {
        $c = New-Object Windows.Controls.TextBlock
        $c.Style = $window.FindResource('TabCount')
        $c.FontFamily = (Get-CEMono); $c.Text = [string]$Count; $c.VerticalAlignment = 'Center'
        [void]$sp.Children.Add($c)
    }
    $Tab.Header = $sp
}

function Set-UiTabsEnabled {
    # Everything but Overview is dimmed while an audit runs.
    param([bool]$On)
    $i = 0
    foreach ($t in $ui.Tabs.Items) { if ($i -gt 0) { $t.IsEnabled = $On }; $i++ }
}

function Set-UiLogOpen {
    param([bool]$On)
    $ui.LogBox.Visibility = if ($On) { 'Visible' } else { 'Collapsed' }
    $ui.ActChevron.Text = [string][char]$(if ($On) { 0x2303 } else { 0x2304 })
}

function ConvertTo-UiText {
    param($Value, [string]$Format = 'd MMM yyyy HH:mm')
    if ($null -eq $Value) { return '' }
    if ($Value -is [datetime]) { return $Value.ToString($Format) }
    # A DateTime deserialized from JSON comes back as an object with a DateTime / value property.
    if ($Value -isnot [string]) {
        $inner = if ($Value.PSObject.Properties['DateTime']) { $Value.DateTime } elseif ($Value.PSObject.Properties['value']) { $Value.value } else { $null }
        if ($inner) {
            $dt = [datetime]::MinValue
            if ([datetime]::TryParse([string]$inner, [ref]$dt)) { return $dt.ToString($Format) }
            return [string]$inner
        }
    }
    return [string]$Value
}

function New-UiTable {
    param([string[]]$Columns, [hashtable]$Types = @{})
    $t = New-Object System.Data.DataTable
    foreach ($c in $Columns) {
        $type = if ($Types.ContainsKey($c)) { $Types[$c] } else { [string] }
        [void]$t.Columns.Add($c, $type)
    }
    # The comma stops PowerShell unrolling the (empty) table into $null.
    return ,$t
}

function ConvertTo-LikeLiteral {
    param([string]$Text)
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $Text.ToCharArray()) {
        if ('[]*%'.IndexOf($ch) -ge 0) { [void]$sb.Append("[$ch]") }
        elseif ($ch -eq "'") { [void]$sb.Append("''") }
        else { [void]$sb.Append($ch) }
    }
    return $sb.ToString()
}

# ---------------------------------------------------------------------------
# Choosing which checks to run
# ---------------------------------------------------------------------------
$chooserXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Choose checks" Width="820" Height="680" MinWidth="620" MinHeight="420"
        WindowStartupLocation="CenterOwner" Background="#F2F4F4" FontFamily="Geist, Segoe UI" FontSize="13" ShowInTaskbar="False">
  <DockPanel Margin="18">
    <StackPanel DockPanel.Dock="Top">
      <TextBlock Text="Choose which checks to run" FontSize="16" FontWeight="SemiBold"/>
      <TextBlock Foreground="#566360" Margin="0,4,0,12" TextWrapping="Wrap"
                 Text="Tick whole control themes or single checks. Running only some checks gives a partial result with no overall verdict; Cyber Essentials only still gives a Cyber Essentials verdict."/>
      <DockPanel Margin="0,0,0,10">
        <StackPanel DockPanel.Dock="Right" Orientation="Horizontal">
          <Button x:Name="AllBtn" Content="All" Padding="12,5" Margin="8,0,0,0"/>
          <Button x:Name="CeBtn" Content="Cyber Essentials only" Padding="12,5" Margin="8,0,0,0"/>
          <Button x:Name="ClearBtn" Content="Clear" Padding="12,5" Margin="8,0,0,0"/>
        </StackPanel>
        <TextBox x:Name="SearchBox" Padding="6,4" VerticalContentAlignment="Center" ToolTip="Filter by check ID, title or framework"/>
      </DockPanel>
    </StackPanel>
    <DockPanel DockPanel.Dock="Bottom" Margin="0,12,0,0">
      <StackPanel DockPanel.Dock="Right" Orientation="Horizontal">
        <Button x:Name="CancelBtn" Content="Cancel" Padding="14,6" Margin="8,0,0,0" IsCancel="True"/>
        <Button x:Name="OkBtn" Content="Use these checks" Padding="14,6" Margin="8,0,0,0" IsDefault="True" Background="#0B0F0E" Foreground="White" FontWeight="SemiBold"/>
      </StackPanel>
      <StackPanel VerticalAlignment="Center">
        <TextBlock x:Name="CountText" FontWeight="SemiBold"/>
        <TextBlock x:Name="AdminText" Foreground="#A9721A" TextWrapping="Wrap"/>
      </StackPanel>
    </DockPanel>
    <Border Background="White" BorderBrush="#E2E8E6" BorderThickness="1" CornerRadius="6">
      <TreeView x:Name="Tree" BorderThickness="0" Padding="6"/>
    </Border>
  </DockPanel>
</Window>
'@

function Get-UiSettingsPath {
    if ($script:UiSettingsPath) { return $script:UiSettingsPath }
    return (Join-Path $env:LOCALAPPDATA 'EngramicBaseline\app-settings.json')
}

function Get-UiCheckGroup {
    <# Control themes (including ones added by packs) with their checks, in report order. #>
    $groups = New-Object System.Collections.ArrayList
    foreach ($category in @(Get-CECategory)) {
        $checks = @(Get-CECheck -Category $category.Id | Sort-Object Id)
        if ($checks.Count) { [void]$groups.Add([pscustomobject]@{ Id = $category.Id; Label = $category.Label; Checks = $checks }) }
    }
    return ,$groups.ToArray()
}

function Get-UiCheckIdsForMode {
    param([ValidateSet('All', 'CE')][string]$Mode)
    $checks = if ($Mode -eq 'CE') { @(Get-CECheck -Framework 'CE') } else { @(Get-CECheck) }
    return ,@($checks | ForEach-Object { $_.Id } | Sort-Object)
}

function Resolve-UiCheckSelection {
    <# Turns ticked check ids into a selection: All, CE (the Cyber Essentials preset) or Custom. #>
    param([AllowEmptyCollection()][string[]]$Ids)
    $known = Get-UiCheckIdsForMode -Mode 'All'
    $chosen = @($Ids | Where-Object { $known -contains $_ } | Sort-Object -Unique)
    $ce = Get-UiCheckIdsForMode -Mode 'CE'
    if ($chosen.Count -eq $known.Count) { return [pscustomobject]@{ Mode = 'All'; Ids = $known } }
    if ($chosen.Count -eq $ce.Count -and -not (Compare-Object -ReferenceObject $ce -DifferenceObject $chosen)) { return [pscustomobject]@{ Mode = 'CE'; Ids = $ce } }
    return [pscustomobject]@{ Mode = 'Custom'; Ids = $chosen }
}

function Get-UiThemeTickState {
    <# $true when every check in the theme is ticked, $false when none are, $null (partly ticked) otherwise. #>
    param([string[]]$ThemeIds, [hashtable]$Ticked)
    $on = @($ThemeIds | Where-Object { $Ticked[$_] }).Count
    if ($on -eq 0) { return $false }
    if ($on -eq @($ThemeIds).Count) { return $true }
    return $null
}

function Get-UiSelectionText {
    param($Selection)
    $total = (Get-UiCheckIdsForMode -Mode 'All').Count
    switch ($Selection.Mode) {
        'All' { return "All $total checks" }
        'CE' { return "Cyber Essentials only ($(@($Selection.Ids).Count) checks)" }
        default { return "$(@($Selection.Ids).Count) of $total checks" }
    }
}

function Read-UiCheckSelection {
    <# The saved choice of checks. Unknown ids (e.g. from a removed pack) are dropped; nothing usable means All. #>
    $path = Get-UiSettingsPath
    try {
        if (Test-Path -LiteralPath $path) {
            $saved = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
            $sel = $saved.checkSelection
            if ($sel.mode -eq 'CE') { return [pscustomobject]@{ Mode = 'CE'; Ids = (Get-UiCheckIdsForMode -Mode 'CE') } }
            if ($sel.mode -eq 'Custom') {
                $resolved = Resolve-UiCheckSelection -Ids @($sel.ids)
                if (@($resolved.Ids).Count) { return $resolved }
            }
        }
    }
    catch { Write-Verbose "Ignoring unreadable settings file $path : $_" }
    return [pscustomobject]@{ Mode = 'All'; Ids = (Get-UiCheckIdsForMode -Mode 'All') }
}

function Save-UiCheckSelection {
    param($Selection)
    $path = Get-UiSettingsPath
    try {
        $dir = Split-Path -Parent $path
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $ids = if ($Selection.Mode -eq 'Custom') { @($Selection.Ids) } else { @() }
        [pscustomobject]@{ checkSelection = [pscustomobject]@{ mode = $Selection.Mode; ids = $ids } } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $path -Encoding UTF8
    }
    catch { Write-UiLog "Could not save the choice of checks: $($_.Exception.Message)" }
}

function Update-UiChooser {
    <# Refreshes theme tick boxes, counts and the admin note in the chooser window. #>
    $ch = $script:Chooser
    $ch.Busy = $true
    try {
        foreach ($g in $ch.Groups) {
            $ids = @($g.Checks | ForEach-Object { $_.Id })
            $ch.ThemeBoxes[$g.Id].IsChecked = Get-UiThemeTickState -ThemeIds $ids -Ticked $ch.Ticked
            $on = @($ids | Where-Object { $ch.Ticked[$_] }).Count
            $ch.ThemeBoxes[$g.Id].Content = "$($g.Label)  ($on of $($ids.Count))"
        }
        foreach ($id in @($ch.CheckBoxes.Keys)) { $ch.CheckBoxes[$id].IsChecked = [bool]$ch.Ticked[$id] }
    }
    finally { $ch.Busy = $false }
    $chosen = @($ch.Ticked.Keys | Where-Object { $ch.Ticked[$_] })
    $selection = Resolve-UiCheckSelection -Ids $chosen
    $ch.Controls.CountText.Text = if ($chosen.Count) { Get-UiSelectionText $selection } else { 'No checks ticked' }
    $needAdmin = @(Get-CECheck -Id $chosen | Where-Object { $_.RequiresAdmin }).Count
    $ch.Controls.AdminText.Text = if ($needAdmin -and -not (Get-CEDeviceContext).IsElevated) { "$needAdmin ticked check(s) need administrator rights and will be skipped. Use Restart as administrator to run them." } else { '' }
    $ch.Controls.OkBtn.IsEnabled = ($chosen.Count -gt 0)
}

function Set-UiChooserFilter {
    $ch = $script:Chooser
    $q = $ch.Controls.SearchBox.Text.Trim()
    foreach ($g in $ch.Groups) {
        $visible = 0
        foreach ($c in $g.Checks) {
            $match = (-not $q) -or ("$($c.Id) $($c.Title) $(@($c.Frameworks) -join ' ')" -like "*$q*")
            $ch.CheckItems[$c.Id].Visibility = if ($match) { 'Visible' } else { 'Collapsed' }
            if ($match) { $visible++ }
        }
        $ch.ThemeItems[$g.Id].Visibility = if ($visible) { 'Visible' } else { 'Collapsed' }
        if ($q) { $ch.ThemeItems[$g.Id].IsExpanded = $true }
    }
}

function Show-CheckChooser {
    <# Opens the Choose checks window. Returns the new selection, or $null when cancelled. #>
    $dlg = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader ([xml]$chooserXaml)))
    Set-CEWindowIcon $dlg
    if ($script:GeistFamily) { $dlg.FontFamily = $script:GeistFamily }
    $dlg.Owner = $window
    $controls = @{}
    foreach ($n in 'AllBtn', 'CeBtn', 'ClearBtn', 'SearchBox', 'CancelBtn', 'OkBtn', 'CountText', 'AdminText', 'Tree') { $controls[$n] = $dlg.FindName($n) }
    $groups = Get-UiCheckGroup
    $ticked = @{}
    $allIds = Get-UiCheckIdsForMode -Mode 'All'
    foreach ($id in $allIds) { $ticked[$id] = (@($script:CheckSelection.Ids) -contains $id) }
    $script:Chooser = @{ Dialog = $dlg; Controls = $controls; Groups = $groups; Ticked = $ticked; ThemeBoxes = @{}; ThemeItems = @{}; CheckBoxes = @{}; CheckItems = @{}; Busy = $false; Result = $null }
    $elevated = (Get-CEDeviceContext).IsElevated

    foreach ($g in $groups) {
        $themeItem = New-Object Windows.Controls.TreeViewItem
        $themeBox = New-Object Windows.Controls.CheckBox
        $themeBox.IsThreeState = $true
        $themeBox.FontWeight = 'SemiBold'
        $themeBox.Margin = '0,4,0,4'
        $themeBox.Tag = $g.Id
        $themeBox.Add_Click({
            param($source)
            $ch = $script:Chooser
            if ($ch.Busy) { return }
            $group = $ch.Groups | Where-Object { $_.Id -eq $source.Tag }
            $visibleIds = @($group.Checks | Where-Object { $ch.CheckItems[$_.Id].Visibility -eq 'Visible' } | ForEach-Object { $_.Id })
            $turnOn = @($visibleIds | Where-Object { -not $ch.Ticked[$_] }).Count -gt 0
            foreach ($id in $visibleIds) { $ch.Ticked[$id] = $turnOn }
            Update-UiChooser
        })
        $themeItem.Header = $themeBox
        $script:Chooser.ThemeBoxes[$g.Id] = $themeBox
        $script:Chooser.ThemeItems[$g.Id] = $themeItem

        foreach ($c in $g.Checks) {
            $row = New-Object Windows.Controls.StackPanel
            $row.Orientation = 'Horizontal'
            $idText = New-Object Windows.Controls.TextBlock
            $idText.Text = $c.Id; $idText.Width = 56; $idText.FontFamily = (Get-CEMono)
            $titleText = New-Object Windows.Controls.TextBlock
            $titleText.Text = $c.Title; $titleText.MaxWidth = 470; $titleText.TextTrimming = 'CharacterEllipsis'; $titleText.ToolTip = $c.Title
            $fwText = New-Object Windows.Controls.TextBlock
            $fwText.Text = "   $(@($c.Frameworks) -join ', ')"; $fwText.Foreground = '#566360'; $fwText.FontSize = 11; $fwText.VerticalAlignment = 'Center'
            [void]$row.Children.Add($idText); [void]$row.Children.Add($titleText); [void]$row.Children.Add($fwText)
            if ($c.RequiresAdmin) {
                $adminText = New-Object Windows.Controls.TextBlock
                $adminText.Text = '  admin'; $adminText.FontSize = 11; $adminText.FontWeight = 'SemiBold'; $adminText.VerticalAlignment = 'Center'
                $adminText.Foreground = if ($elevated) { '#566360' } else { '#A9721A' }
                [void]$row.Children.Add($adminText)
            }
            $box = New-Object Windows.Controls.CheckBox
            $box.Content = $row
            $box.Tag = $c.Id
            $box.Add_Click({
                param($source)
                $ch = $script:Chooser
                if ($ch.Busy) { return }
                $ch.Ticked[[string]$source.Tag] = [bool]$source.IsChecked
                Update-UiChooser
            })
            $checkItem = New-Object Windows.Controls.TreeViewItem
            $checkItem.Header = $box
            [void]$themeItem.Items.Add($checkItem)
            $script:Chooser.CheckBoxes[$c.Id] = $box
            $script:Chooser.CheckItems[$c.Id] = $checkItem
        }
        [void]$controls.Tree.Items.Add($themeItem)
    }

    $setMode = {
        param([string]$Mode)
        $ch = $script:Chooser
        $ids = if ($Mode -eq 'None') { @() } else { Get-UiCheckIdsForMode -Mode $Mode }
        foreach ($id in @($ch.Ticked.Keys)) { $ch.Ticked[$id] = ($ids -contains $id) }
        Update-UiChooser
    }
    $script:Chooser.SetMode = $setMode
    $controls.AllBtn.Add_Click({ & $script:Chooser.SetMode 'All' })
    $controls.CeBtn.Add_Click({ & $script:Chooser.SetMode 'CE' })
    $controls.ClearBtn.Add_Click({ & $script:Chooser.SetMode 'None' })
    $controls.SearchBox.Add_TextChanged({ Set-UiChooserFilter })
    $controls.OkBtn.Add_Click({
        $ch = $script:Chooser
        $ch.Result = Resolve-UiCheckSelection -Ids @($ch.Ticked.Keys | Where-Object { $ch.Ticked[$_] })
        $ch.Dialog.DialogResult = $true
    })

    Update-UiChooser
    [void]$dlg.ShowDialog()
    $result = $script:Chooser.Result
    $script:Chooser = $null
    return $result
}

function Update-UiSelectionText {
    $ui.SelectionText.Text = Get-UiSelectionText $script:CheckSelection
}

# ---------------------------------------------------------------------------
# Background work
# ---------------------------------------------------------------------------
$script:Timer = New-Object Windows.Threading.DispatcherTimer
$script:Timer.Interval = [TimeSpan]::FromMilliseconds(250)
$script:Timer.Add_Tick({
    $job = $script:Job
    if (-not $job) { $script:Timer.Stop(); return }

    $total = [int]$script:Sync.Total
    $done = [int]$script:Sync.Done
    if ($total -gt 0) {
        $ui.Progress.Value = [math]::Min(100, 100 * $done / $total)
        $ui.ActMeta.Text = "$done / $total"
        if ($job.Label -eq 'Audit') { Set-UiVerdict -Head 'Auditing' -Soft "$done of $total checks" -Rail '#3D6AA0' }
    }
    if ($script:Sync.Current) { $ui.StatusText.Text = "$($job.Label): $($script:Sync.Current)" }

    $info = $job.PS.Streams.Information
    while ($job.InfoIndex -lt $info.Count) { Write-UiLog ([string]$info[$job.InfoIndex].MessageData); $job.InfoIndex = $job.InfoIndex + 1 }
    $warn = $job.PS.Streams.Warning
    while ($job.WarnIndex -lt $warn.Count) { Write-UiLog ("WARNING: " + [string]$warn[$job.WarnIndex].Message); $job.WarnIndex = $job.WarnIndex + 1 }

    if ($job.Handle.IsCompleted) {
        $script:Timer.Stop()
        $output = $null
        $failure = $null
        try { $output = $job.PS.EndInvoke($job.Handle) } catch { $failure = $_.Exception.InnerException; if (-not $failure) { $failure = $_.Exception } }
        foreach ($e in $job.PS.Streams.Error) { Write-UiLog "ERROR: $e" }
        $job.PS.Dispose()
        $job.RS.Dispose()
        $script:Job = $null
        Set-UiBusy $false
        if ($failure) {
            $ui.StatusText.Text = "$($job.Label) failed"
            if ($job.Label -eq 'Audit') { Set-UiTabsEnabled $true; Set-UiVerdict -Head 'Audit failed'; $ui.VerdictSub.Text = [string]$failure.Message }
            Write-UiLog "ERROR: $($failure.Message)"
            [void](Show-UiMessage -Text "$($job.Label) failed:`n$($failure.Message)" -Icon 'Error')
            return
        }
        $result = if ($output -and $output.Count) { $output[$output.Count - 1] } else { $null }
        Invoke-UiSafe { & $job.OnComplete $result $job.Context }
    }
})

function Start-UiJob {
    param([string]$Label, [string]$Script, [hashtable]$Arguments, [scriptblock]$OnComplete, [hashtable]$Context = @{})
    if ($script:Job) { return }
    $script:Sync.Current = 'starting'; $script:Sync.Done = 0; $script:Sync.Total = 0
    $rs = [runspacefactory]::CreateRunspace()
    $rs.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript($Script)
    foreach ($k in $Arguments.Keys) { [void]$ps.AddParameter($k, $Arguments[$k]) }
    Set-UiBusy $true "$Label..."
    Write-UiLog "$Label started"
    $script:Job = @{ Label = $Label; PS = $ps; RS = $rs; Handle = $ps.BeginInvoke(); OnComplete = $OnComplete; Context = $Context; InfoIndex = 0; WarnIndex = 0 }
    $script:Timer.Start()
}

$auditScript = @'
param($ModulePath, $OutputPath, $Mode, $CheckIds, $Sync)
$ErrorActionPreference = 'Stop'
Import-Module $ModulePath -Force
$ctx = Get-CEDeviceContext
$fw = $null
$ids = $null
# CE keeps a Cyber Essentials verdict (like -CEOnly); a custom choice is a partial run.
if ($Mode -eq 'CE') { $fw = @('CE') }
elseif ($Mode -eq 'Custom') { $ids = @($CheckIds) }
$findings = @(Invoke-CEAuditCore -Id $ids -Framework $fw -ProgressState $Sync)
$Sync.Current = 'writing reports'
$report = Export-CEReport -Findings $findings -Context $ctx -OutputPath $OutputPath -PartialRun:($Mode -eq 'Custom') -ChecksRun ([int]$Sync.Done)
[pscustomobject]@{ Findings = $findings; Context = $ctx; Summary = $report.Summary; Changeset = $report.Changeset; Folder = $OutputPath; Paths = $report.Paths; AiPosture = (Get-CEAiPosture -Context $ctx) }
'@

$applyScript = @'
param($ModulePath, $ChangesetPath, $ItemIds, $Preview, $Sync)
$ErrorActionPreference = 'Stop'
Import-Module $ModulePath -Force
$cs = Get-Content -LiteralPath $ChangesetPath -Raw | ConvertFrom-Json
$items = @($cs.Items | Where-Object { $ItemIds -contains $_.ItemId })
Invoke-CEChangeset -Items $items -ChangesetPath $ChangesetPath -ProgressState $Sync -WhatIf:$Preview
'@

$rollbackScript = @'
param($ModulePath, $UndoPath)
$ErrorActionPreference = 'Stop'
Import-Module $ModulePath -Force
Restore-CEUndoLog -Path $UndoPath -Confirm:$false
[pscustomobject]@{ Done = $true }
'@

# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------
function Update-DeviceHeader {
    $ctx = Get-CEDeviceContext
    $join = @()
    if ($ctx.DomainJoined) { $join += 'domain joined' }
    if ($ctx.EntraJoined) { $join += 'Entra ID joined' }
    if ($ctx.MdmEnrolled) { $join += 'MDM enrolled' }
    if (-not $join.Count) { $join += 'standalone' }
    $ui.DeviceText.Text = "{0}   |   {1} {2} {3} (build {4})   |   {5}   |   signed in as {6}" -f $ctx.ComputerName, $ctx.OSFamily, $ctx.DisplayVersion, $ctx.EditionID, $ctx.FullBuild, ($join -join ', '), $ctx.RunningAs
    $ui.ElevBadge.Background = Get-Brush '#FFFFFF'
    $ui.ElevBadge.BorderThickness = 1
    if ($ctx.IsElevated) {
        $ui.ElevBadge.BorderBrush = Get-Brush '#008687'
        $ui.ElevText.Text = 'ADMINISTRATOR'
        $ui.ElevText.Foreground = Get-Brush '#006D6E'
        $ui.RestartAdminBtn.Visibility = 'Collapsed'
    }
    else {
        $ui.ElevBadge.BorderBrush = Get-Brush '#A9721A'
        $ui.ElevText.Text = 'STANDARD USER'
        $ui.ElevText.Foreground = Get-Brush '#A9721A'
    }
}

function New-Tile {
    param([string]$Label, [int]$Count, [string]$Fg, [string]$Bg)
    $border = New-Object Windows.Controls.Border
    $border.Background = Get-Brush $Bg
    $border.CornerRadius = New-Object Windows.CornerRadius 8
    $border.Padding = New-Object Windows.Thickness 14, 10, 14, 10
    $border.Margin = New-Object Windows.Thickness 0, 0, 8, 0
    $border.Cursor = [Windows.Input.Cursors]::Hand
    $border.Tag = $Label
    $sp = New-Object Windows.Controls.StackPanel
    $n = New-Object Windows.Controls.TextBlock
    $n.Text = [string]$Count
    $n.FontSize = 26
    $n.FontWeight = 'SemiBold'
    $n.Foreground = Get-Brush $Fg
    $l = New-Object Windows.Controls.TextBlock
    $l.Text = if ($Label -eq 'NotApplicable') { 'Not applicable' } else { $Label }
    $l.Foreground = Get-Brush $Fg
    [void]$sp.Children.Add($n)
    [void]$sp.Children.Add($l)
    $border.Child = $sp
    $border.Add_MouseLeftButtonUp({
        param($s, $e)
        $ui.StatusFilter.SelectedItem = [string]$s.Tag
        $ui.Tabs.SelectedItem = $ui.FindingsTab
    })
    return $border
}

function New-CELegendItem {
    param([string]$Colour, [string]$Text)
    $sp = New-Object Windows.Controls.StackPanel
    $sp.Orientation = 'Horizontal'; $sp.Margin = '0,0,16,0'
    $sq = New-Object Windows.Controls.Border
    $sq.Width = 11; $sq.Height = 11; $sq.Background = Get-Brush $Colour; $sq.BorderBrush = Get-Brush '#E2E8E6'; $sq.BorderThickness = 1; $sq.Margin = '0,0,6,0'; $sq.VerticalAlignment = 'Center'
    [void]$sp.Children.Add($sq)
    $tb = New-Object Windows.Controls.TextBlock; $tb.Text = $Text; $tb.FontSize = 11.5; $tb.Foreground = Get-Brush '#566360'; $tb.VerticalAlignment = 'Center'
    [void]$sp.Children.Add($tb)
    return $sp
}

function Set-CEStatusStack {
    # Neutral IBCS-style stacked bar: met (ink) | attention (red) | confirm (grey) | n/a (light).
    param($Summary)
    $by = $Summary.ByStatus
    $met = [int]$by.Pass
    $attention = [int]$by.Fail + [int]$by.Warn + [int]$by.Error
    $confirm = [int]$by.Manual
    $na = [int]$by.Skipped + [int]$by.NotApplicable + [int]$by.Info
    $bs = Get-CEBucketStyle
    $segs = @(
        [pscustomobject]@{ N = $met; C = $bs['met'].Light; T = "$met met"; Fg = '#FFFFFF' }
        [pscustomobject]@{ N = $attention; C = $bs['attention'].Light; T = "$attention"; Fg = '#FFFFFF' }
        [pscustomobject]@{ N = $confirm; C = $bs['confirm'].Light; T = "$confirm confirm"; Fg = '#FFFFFF' }
        [pscustomobject]@{ N = $na; C = '#E2E8E6'; T = "$na"; Fg = '#566360' }
    )
    $grid = New-Object Windows.Controls.Grid
    $i = 0
    foreach ($s in $segs) {
        $cd = New-Object Windows.Controls.ColumnDefinition
        $cd.Width = New-Object Windows.GridLength([double]([math]::Max(0, $s.N)), ([Windows.GridUnitType]::Star))
        $grid.ColumnDefinitions.Add($cd)
        if ($s.N -gt 0) {
            $b = New-Object Windows.Controls.Border; $b.Background = Get-Brush $s.C
            $tb = New-Object Windows.Controls.TextBlock
            $tb.Text = $s.T; $tb.Foreground = Get-Brush $s.Fg; $tb.FontFamily = (Get-CEMono); $tb.FontSize = 11; $tb.FontWeight = 'SemiBold'
            $tb.HorizontalAlignment = 'Center'; $tb.VerticalAlignment = 'Center'; $tb.Margin = '4,0,4,0'; $tb.TextTrimming = 'CharacterEllipsis'
            $b.Child = $tb
            [Windows.Controls.Grid]::SetColumn($b, $i); [void]$grid.Children.Add($b)
        }
        $i++
    }
    $ui.StatusStack.Child = $grid
    $ui.StatusLegend.Children.Clear()
    [void]$ui.StatusLegend.Children.Add((New-CELegendItem -Colour $bs['met'].Light -Text "Met $met"))
    [void]$ui.StatusLegend.Children.Add((New-CELegendItem -Colour $bs['attention'].Light -Text "Attention $attention"))
    [void]$ui.StatusLegend.Children.Add((New-CELegendItem -Colour $bs['confirm'].Light -Text "To confirm $confirm"))
    [void]$ui.StatusLegend.Children.Add((New-CELegendItem -Colour '#E2E8E6' -Text "Skipped / n/a $na"))
}

function New-CEFrameworkBar {
    # One framework row: label | fraction | neutral bar (filled to %) | % | deviation.
    param([string]$Label, [string]$Fraction, [int]$Percent, [int]$Deviation, [switch]$NotRun)
    $grid = New-Object Windows.Controls.Grid
    $grid.Margin = '0,4,0,4'
    foreach ($w in 190, 74, -1, 46, 56) {
        $cd = New-Object Windows.Controls.ColumnDefinition
        $cd.Width = if ($w -lt 0) { New-Object Windows.GridLength(1, ([Windows.GridUnitType]::Star)) } else { New-Object Windows.GridLength([double]$w) }
        $grid.ColumnDefinitions.Add($cd)
    }
    $lab = New-Object Windows.Controls.TextBlock
    $lab.Text = $Label; $lab.VerticalAlignment = 'Center'; $lab.TextTrimming = 'CharacterEllipsis'
    if ($NotRun) { $lab.Foreground = Get-Brush '#566360' }
    [Windows.Controls.Grid]::SetColumn($lab, 0); [void]$grid.Children.Add($lab)

    $fr = New-Object Windows.Controls.TextBlock
    $fr.Text = $Fraction; $fr.FontFamily = (Get-CEMono); $fr.FontSize = 11.5
    $fr.Foreground = Get-Brush '#566360'; $fr.HorizontalAlignment = 'Right'; $fr.VerticalAlignment = 'Center'; $fr.Margin = '0,0,10,0'
    [Windows.Controls.Grid]::SetColumn($fr, 1); [void]$grid.Children.Add($fr)

    $p = [math]::Max(0, [math]::Min(100, $Percent))
    $track = New-Object Windows.Controls.Border
    $track.Height = 15; $track.Background = Get-Brush '#E2E8E6'; $track.Margin = '0,0,10,0'
    $inner = New-Object Windows.Controls.Grid
    $c1 = New-Object Windows.Controls.ColumnDefinition; $c1.Width = New-Object Windows.GridLength([double]$p, ([Windows.GridUnitType]::Star))
    $c2 = New-Object Windows.Controls.ColumnDefinition; $c2.Width = New-Object Windows.GridLength([double](100 - $p), ([Windows.GridUnitType]::Star))
    $inner.ColumnDefinitions.Add($c1); $inner.ColumnDefinitions.Add($c2)
    $fill = New-Object Windows.Controls.Border; $fill.Background = Get-Brush ((Get-CEBucketStyle 'met').Light)
    if ($NotRun) { $track.Opacity = 0.45; $fill.Background = $null }
    [Windows.Controls.Grid]::SetColumn($fill, 0); [void]$inner.Children.Add($fill)
    $track.Child = $inner
    [Windows.Controls.Grid]::SetColumn($track, 2); [void]$grid.Children.Add($track)

    $pc = New-Object Windows.Controls.TextBlock
    $pc.Text = "$p%"; $pc.FontFamily = (Get-CEMono); $pc.FontWeight = 'Bold'; $pc.HorizontalAlignment = 'Right'; $pc.VerticalAlignment = 'Center'
    if ($NotRun) { $pc.Text = 'not run'; $pc.FontWeight = 'Normal'; $pc.FontSize = 11.5; $pc.Foreground = Get-Brush '#566360'; [Windows.Controls.Grid]::SetColumnSpan($pc, 2) }
    [Windows.Controls.Grid]::SetColumn($pc, 3); [void]$grid.Children.Add($pc)

    $dv = New-Object Windows.Controls.TextBlock
    $dv.FontFamily = (Get-CEMono); $dv.FontSize = 12; $dv.FontWeight = 'SemiBold'; $dv.HorizontalAlignment = 'Right'; $dv.VerticalAlignment = 'Center'
    if ($Deviation -gt 0 -and -not $NotRun) { $dv.Text = ([char]0x25BC) + " $Deviation"; $dv.Foreground = Get-Brush '#A9721A' }
    else { $dv.Text = $(if ($NotRun) { '' } else { '-' }); $dv.Foreground = Get-Brush '#566360' }
    [Windows.Controls.Grid]::SetColumn($dv, 4); [void]$grid.Children.Add($dv)
    return $grid
}

function New-CEAiLine {
    param([string]$Text, [switch]$Bad)
    $tb = New-Object Windows.Controls.TextBlock
    $tb.Text = $Text; $tb.Margin = '0,2,0,2'; $tb.TextWrapping = 'Wrap'
    if ($Bad) { $tb.Foreground = Get-Brush '#C23F2C'; $tb.FontWeight = 'SemiBold' } else { $tb.Foreground = Get-Brush '#0B0F0E' }
    return $tb
}

function Set-CEAiTab {
    param($Ai, $Findings)
    $dev = [int]$Ai.deviations
    $ui.AiSummary.Text = "$($Ai.agentsFound) AI tool(s) found - " + $(if ($Ai.contained) { 'contained (none running as administrator, no root distribution)' } else { "$dev deviation(s)" })
    $ui.AiSummary.Foreground = if ($Ai.contained) { Get-Brush '#006D6E' } else { Get-Brush '#C23F2C' }

    $ui.AiAgents.Children.Clear()
    foreach ($a in @($Ai.agents)) {
        $bad = [bool]($a.elevated -or $a.asSystem)
        $state = if ($bad) { 'running as administrator' } elseif ($a.running) { 'running, standard user' } else { 'present' }
        [void]$ui.AiAgents.Children.Add((New-CEAiLine -Text "$($a.name) - $state" -Bad:$bad))
    }
    if (@($Ai.agents).Count -eq 0) { [void]$ui.AiAgents.Children.Add((New-CEAiLine -Text 'No AI tools detected in this session.')) }

    $ui.AiEnvs.Children.Clear()
    foreach ($env in @($Ai.environments)) {
        if ($env.type -eq 'wsl') {
            $root = if ($env.defaultUidRoot) { 'defaults to root' } else { 'non-root' }
            $extra = "$(if ($env.autoMount) { ', Windows drives mounted' })$(if ($env.networking) { ", networking: $($env.networking)" })"
            [void]$ui.AiEnvs.Children.Add((New-CEAiLine -Text "WSL $($env.wslVersion): $($env.name) - $root$extra" -Bad:([bool]$env.defaultUidRoot)))
        }
        else { [void]$ui.AiEnvs.Children.Add((New-CEAiLine -Text "$($env.type): $($env.name)")) }
    }
    if (@($Ai.environments).Count -eq 0) { [void]$ui.AiEnvs.Children.Add((New-CEAiLine -Text 'No VMs, WSL distributions or containers found.')) }

    $ct = New-UiTable @('ID', 'Status', 'Check')
    foreach ($f in @($Findings | Where-Object { [string]$_.Scope -eq 'User' })) {
        $title = if ($f.Subject) { "$($f.Title) ($($f.Subject))" } else { [string]$f.Title }
        [void]$ct.Rows.Add([string]$f.CheckId, [string]$f.Status, $title)
    }
    $ui.AiControls.ItemsSource = $ct.DefaultView

    if ($ui.AiLine) {
        $n = [int]$Ai.agentsFound
        $parts = @(@{ Text = "$n AI tool$(if ($n -ne 1) { 's' }) found, " })
        if ($Ai.contained) { $parts += @{ Text = 'contained'; Colour = '#006D6E'; Weight = 'SemiBold' } }
        else { $parts += @{ Text = "$dev running with elevated rights"; Colour = '#C23F2C'; Weight = 'SemiBold' } }
        Set-UiRichText -Block $ui.AiLineText -Parts $parts
        $ui.AiLine.Visibility = 'Visible'
    }
}

function Set-CEFrameworkBars {
    param($Panel, $Rollup)
    $Panel.Children.Clear()
    foreach ($k in $Rollup.Keys) {
        $x = $Rollup[$k]
        if ($k -eq 'ce-plus') {
            $pct = if ([int]$x.total -gt 0) { [int][math]::Round(([double]$x.onTrack / $x.total) * 100) } else { 0 }
            $frac = "$($x.onTrack) / $($x.total) TCs"
            $dev = [int]$x.total - [int]$x.onTrack
        }
        else {
            $pct = [int]$x.metPct; $frac = "$($x.met) / $($x.applicable)"; $dev = [int]$x.attention + [int]$x.confirm
            if ([int]$x.applicable -eq 0) {
                [void]$Panel.Children.Add((New-CEFrameworkBar -Label ([string]$x.label) -Fraction '-' -Percent 0 -Deviation 0 -NotRun))
                continue
            }
        }
        [void]$Panel.Children.Add((New-CEFrameworkBar -Label ([string]$x.label) -Fraction $frac -Percent $pct -Deviation $dev))
    }
}

function Show-Results {
    param($Result)
    $script:Current = $Result
    $summary = $Result.Summary
    $findings = @($Result.Findings)

    # Message banner + framework bars (no single verdict; each framework judges itself)
    $checkMap = Get-CEStatusCheckMap -Findings $findings
    $roll = Get-CEFrameworkRollup -CheckMap $checkMap -Summary $summary
    $attn = @($checkMap.Keys | Where-Object { @('Fail', 'Warn', 'Error') -contains [string]$checkMap[$_].status }).Count
    $confirm = @($checkMap.Keys | Where-Object { [string]$checkMap[$_].status -eq 'Manual' }).Count
    $ui.VerdictText.Foreground = Get-Brush '#0B0F0E'
    $when = ConvertTo-UiText $Result.Context.AuditTime
    $elevated = [bool]$Result.Context.IsElevated
    $soft = if ($confirm) { "$confirm to confirm" } else { '' }
    $sub = @(@{ Text = "Audited $when as $($Result.Context.RunningAs)" })
    if ($summary.PartialRun) {
        $m = [regex]::Match([string]$summary.Verdict, '(\d+) of (\d+)')
        $ran = if ($m.Success) { $m.Groups[1].Value } else { '?' }
        $all = if ($m.Success) { $m.Groups[2].Value } else { (Get-UiCheckIdsForMode -Mode 'All').Count }
        Set-UiVerdict -Head 'Partial audit' -Soft "$ran of $all checks run" -Rail '#B8C4C0'
        $sub += @{ Text = $(if ($elevated) { '. ' } else { '. Standard user, so admin-only checks were skipped. ' }) }
        $sub += @{ Text = "Run all $all checks"; Link = { Invoke-UiSafe { $script:CheckSelection = [pscustomobject]@{ Mode = 'All'; Ids = (Get-UiCheckIdsForMode -Mode 'All') }; Save-UiCheckSelection $script:CheckSelection; Update-UiSelectionText; Start-Audit } } }
    }
    elseif ($attn) {
        Set-UiVerdict -Head "$attn control$(if ($attn -ne 1) { 's' }) need attention" -Soft $soft -Rail '#A9721A'
    }
    else {
        Set-UiVerdict -Head 'All controls met' -Soft $soft -Rail '#008687'
    }
    if (-not $summary.PartialRun) {
        if ($elevated) { $sub += @{ Text = ', run as administrator.' } }
        else {
            $sub += @{ Text = '. Standard user, so admin-only checks were skipped. ' }
            $sub += @{ Text = 'Restart as administrator'; Link = { Invoke-UiSafe { $ui.RestartAdminBtn.RaiseEvent((New-Object Windows.RoutedEventArgs ([Windows.Controls.Button]::ClickEvent))) } } }
        }
    }
    Set-UiRichText -Block $ui.VerdictSub -Parts $sub
    $ui.ActMeta.Text = "last audit $(ConvertTo-UiText $Result.Context.AuditTime -Format 'HH:mm') " + [char]0xB7 + " $(@($checkMap.Keys).Count) check$(if (@($checkMap.Keys).Count -ne 1) { 's' })"
    $ui.OvEmpty.Visibility = 'Collapsed'
    $ui.OvBody.Visibility = 'Visible'
    Set-UiTabsEnabled $true

    Set-CEFrameworkBars -Panel $ui.FwBars -Rollup $roll

    # AI tab: use the posture computed in the audit runspace; recompute live for saved results.
    $ai = if ($Result.PSObject.Properties['AiPosture'] -and $Result.AiPosture) { $Result.AiPosture } else { Get-CEAiPosture }
    Set-CEAiTab -Ai $ai -Findings $findings

    # Controls by status (neutral stacked bar)
    Set-CEStatusStack -Summary $summary

    # CE+ readiness
    $tc = New-UiTable @('Test', 'Name', 'Scope', 'Status')
    foreach ($t in @($summary.CEPlus)) { [void]$tc.Rows.Add($t.TestCase, $t.Name, $t.Scope, $(if ($t.State -eq 'Not assessed') { 'Skipped' } else { $t.State })) }
    $ui.TcGrid.ItemsSource = $tc.DefaultView

    # Themes
    $th = New-UiTable @('Theme', 'Pass', 'Fail', 'Warn', 'Manual', 'Other') @{ Pass = [int]; Fail = [int]; Warn = [int]; Manual = [int]; Other = [int] }
    foreach ($c in @($summary.ByCategory)) { [void]$th.Rows.Add($themeLabels[[string]$c.Category], $c.Pass, $c.Fail, $c.Warn, $c.Manual, $c.Other) }
    $ui.ThemeGrid.ItemsSource = $th.DefaultView

    # Findings
    $script:FindingIndex = @{}
    $ft = New-UiTable @('FindingId', 'CheckId', 'Status', 'AutoFail', 'Severity', 'SeverityRank', 'Title', 'Actual', 'Frameworks', 'Category') @{ AutoFail = [bool]; SeverityRank = [int] }
    $rank = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
    $statusRank = @{ Fail = 0; Error = 1; Warn = 2; Manual = 3; Skipped = 4; Pass = 5; NotApplicable = 6; Info = 7 }
    foreach ($f in ($findings | Sort-Object @{ e = { $statusRank[[string]$_.Status] } }, @{ e = { $rank[[string]$_.Severity] } }, CheckId)) {
        $title = if ($f.Subject) { "$($f.Title) ($($f.Subject))" } else { $f.Title }
        [void]$ft.Rows.Add($f.FindingId, $f.CheckId, $f.Status, [bool]$f.AutoFail, $f.Severity, $rank[[string]$f.Severity], $title, $f.Actual, (@($f.Frameworks) -join ', '), $f.Category)
        $script:FindingIndex[[string]$f.FindingId] = $f
    }
    $ui.FindingsGrid.ItemsSource = $ft.DefaultView
    Update-FindingFilter

    # Changeset
    $script:ChangeIndex = @{}
    $ct = New-UiTable @('Selected', 'ItemId', 'Title', 'AutoFail', 'Severity', 'Risk', 'Reboot', 'Admin', 'Why', 'Recommended') @{ Selected = [bool]; AutoFail = [bool]; Recommended = [bool] }
    foreach ($i in @($Result.Changeset.Items)) {
        $rem = Get-CERemediation -Id $i.RemediationId
        $recommended = if ($rem) { [bool]$rem.SelectedByDefault } else { $false }
        [void]$ct.Rows.Add([bool]$i.Selected, $i.ItemId, $i.Title, [bool]$i.AutoFail, $i.Severity, $i.Risk, $(if ($i.RequiresReboot) { 'Yes' } else { '' }), $(if ($i.RequiresAdmin) { 'Yes' } else { '' }), $i.Why, $recommended)
        $script:ChangeIndex[[string]$i.ItemId] = $i
    }
    $ct.Add_ColumnChanged({ Update-SelectionCount })
    $ui.ChangesGrid.ItemsSource = $ct.DefaultView
    Set-UiTabHeader -Tab $ui.ChangesTab -Label 'Fixes' -Count (@($Result.Changeset.Items).Count)
    Update-SelectionCount

    # Manual actions
    $mt = New-UiTable @('Status', 'AutoFail', 'Severity', 'Title', 'Actual', 'Recommendation') @{ AutoFail = [bool] }
    foreach ($m in @($Result.Changeset.ManualActions)) { [void]$mt.Rows.Add($m.Status, [bool]$m.AutoFail, $m.Severity, $m.Title, $m.Actual, $m.Recommendation) }
    $ui.ManualGrid.ItemsSource = $mt.DefaultView
    Set-UiTabHeader -Tab $ui.ManualTab -Label 'Manual actions' -Count (@($Result.Changeset.ManualActions).Count)

    $ui.OpenReportBtn.IsEnabled = [bool]($Result.Paths -and (Test-Path -LiteralPath $Result.Paths.Html))
    $ui.OpenFolderBtn.IsEnabled = [bool]($Result.Folder -and (Test-Path -LiteralPath $Result.Folder))
    Update-History
}

function Update-FindingFilter {
    $view = $ui.FindingsGrid.ItemsSource
    if (-not $view) { return }
    $parts = @()
    $theme = [string]$ui.ThemeFilter.SelectedValue
    if ($theme -and $theme -ne '(all)') {
        $key = ($themeLabels.GetEnumerator() | Where-Object { $_.Value -eq $theme } | Select-Object -First 1).Key
        if ($key) { $parts += "Category = '$key'" }
    }
    $status = [string]$ui.StatusFilter.SelectedValue
    if ($status -eq 'Needs action') { $parts += "Status IN ('Fail','Warn','Manual','Error')" }
    elseif ($status -and $status -ne '(all)') { $parts += "Status = '$status'" }
    $q = $ui.SearchBox.Text.Trim()
    if ($q) {
        $like = ConvertTo-LikeLiteral $q
        $parts += "(Title LIKE '%$like%' OR Actual LIKE '%$like%' OR FindingId LIKE '%$like%' OR Frameworks LIKE '%$like%')"
    }
    $view.RowFilter = ($parts -join ' AND ')
    $ui.FindingCount.Text = "$($view.Count) of $($view.Table.Rows.Count) shown"
}

function Update-SelectionCount {
    $view = $ui.ChangesGrid.ItemsSource
    if (-not $view) { $ui.SelCount.Text = ''; return }
    $rows = @($view.Table.Rows)
    $sel = @($rows | Where-Object { $_['Selected'] })
    $high = @($sel | Where-Object { $_['Risk'] -eq 'High' }).Count
    $reboot = @($sel | Where-Object { $_['Reboot'] -eq 'Yes' }).Count
    $text = "$($sel.Count) of $($rows.Count) ticked"
    if ($reboot) { $text += ", $reboot need a restart" }
    if ($high) { $text += ", $high HIGH RISK" }
    $ui.SelCount.Text = $text
}

function Update-History {
    $logs = @(Get-CEUndoLogs -OutputRoot $script:OutputRoot | Where-Object { -not $_.Computer -or $_.Computer -eq $env:COMPUTERNAME })
    $ht = New-UiTable @('AppliedAt', 'AppliedBy', 'Items', 'Summary', 'Path') @{ Items = [int] }
    foreach ($l in $logs) { [void]$ht.Rows.Add($l.AppliedAt.ToString('yyyy-MM-dd HH:mm:ss'), $l.AppliedBy, $l.Items, $l.Summary, $l.Path) }
    $ui.HistoryGrid.ItemsSource = $ht.DefaultView
    if ($ui.HistEmpty) { $ui.HistEmpty.Visibility = if ($logs.Count -eq 0) { 'Visible' } else { 'Collapsed' } }
    Set-UiTabHeader -Tab $ui.HistoryTab -Label 'History' -Count $logs.Count
}

function Import-SavedResults {
    param([string]$FindingsPath)
    $folder = Split-Path -Parent $FindingsPath
    $data = Get-Content -LiteralPath $FindingsPath -Raw | ConvertFrom-Json
    $csPath = Join-Path $folder 'changeset.json'
    $cs = if (Test-Path -LiteralPath $csPath) { Get-Content -LiteralPath $csPath -Raw | ConvertFrom-Json } else { [pscustomobject]@{ Items = @(); ManualActions = @() } }
    $ctx = $data.Context
    if ($ctx.AuditTime -and $ctx.AuditTime -isnot [datetime]) {
        $parsed = [datetime]::MinValue
        if ([datetime]::TryParse([string]$ctx.AuditTime, [ref]$parsed)) { $ctx.AuditTime = $parsed }
    }
    return [pscustomobject]@{
        Findings  = @($data.Findings)
        Context   = $ctx
        Summary   = $data.Summary
        Changeset = $cs
        Folder    = $folder
        Paths     = [pscustomobject]@{ Findings = $FindingsPath; Changeset = $csPath; Html = (Join-Path $folder 'report.html'); Markdown = (Join-Path $folder 'report.md') }
    }
}

function Save-Selections {
    <# Writes the ticked state back into changeset.json so the file matches what was applied. #>
    $view = $ui.ChangesGrid.ItemsSource
    foreach ($r in $view.Table.Rows) { $r.EndEdit() }
    $selected = @{}
    foreach ($r in $view.Table.Rows) { $selected[[string]$r['ItemId']] = [bool]$r['Selected'] }
    $path = $script:Current.Paths.Changeset
    $cs = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    foreach ($i in @($cs.Items)) { if ($selected.ContainsKey([string]$i.ItemId)) { $i.Selected = $selected[[string]$i.ItemId] } }
    $cs | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $path -Encoding UTF8
    return @($selected.Keys | Where-Object { $selected[$_] } | Sort-Object)
}

# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------
function Start-Audit {
    $ctx = Get-CEDeviceContext
    $folder = Join-Path $script:OutputRoot ("{0}-{1}" -f $ctx.ComputerName, (Get-Date -Format 'yyyyMMdd-HHmmss'))
    Set-UiVerdict -Head 'Auditing' -Soft 'starting' -Rail '#3D6AA0'
    $ui.VerdictSub.Text = 'Reading settings only. You can keep using the device.'
    $ui.AiLine.Visibility = 'Collapsed'
    $ui.OvEmptyTitle.Text = 'Results appear as the audit finishes'
    $ui.OvEmptyText.Text = 'About a minute on a typical laptop; longer when winget has to refresh its sources.'
    $ui.OvBody.Visibility = 'Collapsed'; $ui.OvEmpty.Visibility = 'Visible'
    $ui.Tabs.SelectedIndex = 0
    Set-UiTabsEnabled $false
    Start-UiJob -Label 'Audit' -Script $auditScript -Arguments @{
        ModulePath = $script:ModulePath; OutputPath = $folder; Mode = $script:CheckSelection.Mode; CheckIds = @($script:CheckSelection.Ids); Sync = $script:Sync
    } -OnComplete {
        param($r)
        if (-not $r) { throw 'The audit returned no results.' }
        Show-Results $r
        $ui.StatusText.Text = "Audit complete: $(@($r.Findings).Count) results"
        Write-UiLog "Audit complete. Results saved to $($r.Folder)"
        $ui.Tabs.SelectedIndex = 0
    }
}

function Start-Apply {
    param([bool]$Preview)
    if (-not $script:Current) { throw 'Run an audit first.' }
    if ($script:Current.Context.ComputerName -ne $env:COMPUTERNAME) { throw "These results are for $($script:Current.Context.ComputerName). Run an audit on this device first." }
    $ids = Save-Selections
    if (-not $ids.Count) { [void](Show-UiMessage 'Tick at least one fix first.'); return }

    $items = @($ids | ForEach-Object { $script:ChangeIndex[$_] })
    $ctx = Get-CEDeviceContext
    $high = @($items | Where-Object Risk -eq 'High')
    $needAdmin = @($items | Where-Object RequiresAdmin)
    $reboot = @($items | Where-Object RequiresReboot)

    if (-not $Preview) {
        $msg = "Apply $($items.Count) fix(es) to $($ctx.ComputerName)?`n"
        if ($reboot.Count) { $msg += "`n- $($reboot.Count) need a restart afterwards." }
        if ($needAdmin.Count -and -not $ctx.IsElevated) { $msg += "`n- $($needAdmin.Count) need administrator rights and will be SKIPPED (use Restart as administrator)." }
        if ($ctx.CentrallyManaged) { $msg += "`n- This device is centrally managed; policy may undo some changes." }
        if ($high.Count) { $msg += "`n`nHIGH RISK fixes ticked:`n" + (($high | ForEach-Object { "  $($_.ItemId) $($_.Title)" }) -join "`n") }
        $msg += "`n`nEvery change is logged and can be rolled back from the History tab."
        $icon = if ($high.Count) { 'Warning' } else { 'Question' }
        if ((Show-UiMessage -Text $msg -Buttons 'YesNo' -Icon $icon) -ne 'Yes') { return }
    }

    $label = if ($Preview) { 'Preview' } else { 'Apply' }
    Start-UiJob -Label $label -Script $applyScript -Arguments @{
        ModulePath = $script:ModulePath; ChangesetPath = $script:Current.Paths.Changeset; ItemIds = $ids; Preview = $Preview; Sync = $script:Sync
    } -OnComplete {
        param($r)
        if ($r.WhatIf) {
            $ui.StatusText.Text = 'Preview complete: nothing was changed'
            Set-UiLogOpen $true
            return
        }
        $logFile = Join-Path $script:Current.Folder ("apply-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
        Set-Content -LiteralPath $logFile -Value $ui.LogBox.Text -Encoding UTF8
        $lines = @("Applied: $($r.Applied)   Failed: $($r.Failed)   Skipped: $($r.Skipped)")
        foreach ($x in @($r.Results | Where-Object { $_.Status -ne 'Applied' })) { $lines += "$($x.ItemId) $($x.Status): $($x.Message)" }
        if (@($r.Verification).Count) {
            $still = @($r.Verification | Where-Object { @('Fail', 'Warn') -contains $_.Status })
            $lines += ''
            $lines += "Re-checked $(@($r.Verification).Count) result(s): $($still.Count) still need attention" + $(if ($r.NeedsReboot) { ' (some only clear after a restart)' } else { '' }) + '.'
        }
        if ($r.NeedsReboot) { $lines += ''; $lines += 'Restart the device to finish, then run the audit again.' }
        $ui.StatusText.Text = "Applied $($r.Applied) fix(es)"
        Update-History
        $answer = Show-UiMessage -Text (($lines -join "`n") + "`n`nRun the audit again now?") -Buttons 'YesNo' -Icon 'Information'
        if ($answer -eq 'Yes') { Start-Audit }
    }
}

function Start-Rollback {
    $row = $ui.HistoryGrid.SelectedItem
    if (-not $row) { [void](Show-UiMessage 'Select an entry in the list first.'); return }
    $path = [string]$row['Path']
    $msg = "Roll back these changes?`n`n$($row['Summary'])`n`nSettings will be restored to what they were before. Some changes need a restart."
    if ((Show-UiMessage -Text $msg -Buttons 'YesNo' -Icon 'Warning') -ne 'Yes') { return }
    Start-UiJob -Label 'Rollback' -Script $rollbackScript -Arguments @{ ModulePath = $script:ModulePath; UndoPath = $path } -Context @{ Path = $path } -OnComplete {
        param($r, $jobContext)
        $undoFile = $jobContext.Path
        try { Move-Item -LiteralPath $undoFile -Destination "$undoFile.rolledback" -Force } catch { Write-UiLog "Could not rename undo log: $_" }
        Update-History
        $ui.StatusText.Text = 'Rollback complete'
        $answer = Show-UiMessage -Text "Rollback complete. Restart if any of the changes needed one.`n`nRun the audit again now?" -Buttons 'YesNo'
        if ($answer -eq 'Yes') { Start-Audit }
    }
}

# ---------------------------------------------------------------------------
# Wire up
# ---------------------------------------------------------------------------
$ui.ThemeFilter.ItemsSource = @('(all)') + @($themeLabels.Values)
$ui.ThemeFilter.SelectedIndex = 0
$ui.StatusFilter.ItemsSource = @('(all)', 'Needs action') + $statusOrder
$ui.StatusFilter.SelectedIndex = 0

$ui.ThemeFilter.Add_SelectionChanged({ Update-FindingFilter })
$ui.StatusFilter.Add_SelectionChanged({ Update-FindingFilter })
$ui.SearchBox.Add_TextChanged({ Update-FindingFilter })

$ui.FindingsGrid.Add_SelectionChanged({
    $row = $ui.FindingsGrid.SelectedItem
    if (-not $row) { return }
    $f = $script:FindingIndex[[string]$row['FindingId']]
    if (-not $f) { return }
    $ui.DetTitle.Text = "$($f.FindingId)  -  $($row['Title'])"
    $ui.DetRef.Text = "$(@($f.Frameworks) -join ', ')  |  $($f.Reference)"
    $ui.DetExpected.Text = [string]$f.Expected
    $ui.DetActual.Text = [string]$f.Actual
    $ui.DetRec.Text = if ($f.Recommendation) { [string]$f.Recommendation } else { 'No action needed.' }
    $fix = ''
    if ($f.Remediation) {
        $item = @($script:ChangeIndex.Values | Where-Object { @($_.FindingIds) -contains $f.FindingId }) | Select-Object -First 1
        if ($item) { $fix = "Automated fix available: $($item.ItemId) $($item.Title) (see the Fixes tab)" }
    }
    $ui.DetFix.Text = $fix
    $ui.DetEvidence.Text = (@($f.Evidence) | ForEach-Object { [string]$_ }) -join "`r`n"
})

$ui.ChangesGrid.Add_SelectionChanged({
    $row = $ui.ChangesGrid.SelectedItem
    if (-not $row -or $row -isnot [System.Data.DataRowView]) { return }
    $i = $script:ChangeIndex[[string]$row['ItemId']]
    if (-not $i) { return }
    $bits = @("$($i.ItemId): $($i.Title)", "Fixes: $(@($i.FindingIds) -join ', ')", "Remediation: $($i.RemediationId)  |  Risk: $($i.Risk)  |  Reversible: $($i.Reversible)")
    if ($i.Notes) { $bits += "Note: $($i.Notes)" }
    $ui.ChangeNotes.Text = $bits -join "`n"
})

foreach ($tab in $ui.Tabs.Items) { if ($tab.Header -is [string]) { Set-UiTabHeader -Tab $tab -Label $tab.Header } }
$ui.RunBtn.Add_Click({ Invoke-UiSafe { Start-Audit } })
$ui.ActBar.Add_MouseLeftButtonUp({ Set-UiLogOpen ($ui.LogBox.Visibility -ne 'Visible') })
$ui.AiTabLink.Add_Click({ $ui.Tabs.SelectedIndex = 1 })
$ui.ChooseChecksBtn.Add_Click({
    Invoke-UiSafe {
        $choice = Show-CheckChooser
        if ($choice) {
            $script:CheckSelection = $choice
            Save-UiCheckSelection $choice
            Update-UiSelectionText
            Write-UiLog "Checks to run: $(Get-UiSelectionText $choice)"
        }
    }
})
$ui.PreviewBtn.Add_Click({ Invoke-UiSafe { Start-Apply -Preview $true } })
$ui.ApplyBtn.Add_Click({ Invoke-UiSafe { Start-Apply -Preview $false } })
$ui.RollbackBtn.Add_Click({ Invoke-UiSafe { Start-Rollback } })
$ui.HistRefreshBtn.Add_Click({ Invoke-UiSafe { Update-History } })

$setTicks = {
    param([scriptblock]$Rule)
    $view = $ui.ChangesGrid.ItemsSource
    if (-not $view) { return }
    foreach ($r in $view.Table.Rows) { $r['Selected'] = [bool](& $Rule $r) }
    Update-SelectionCount
}
$ui.SelRecBtn.Add_Click({ & $setTicks { param($r) $r['Recommended'] } })
$ui.SelAutoBtn.Add_Click({ & $setTicks { param($r) $r['AutoFail'] -and $r['Risk'] -ne 'High' } })
$ui.SelNoneBtn.Add_Click({ & $setTicks { param($r) $false } })

$ui.OpenReportBtn.Add_Click({ Invoke-UiSafe { Start-Process $script:Current.Paths.Html } })
$ui.MoreBtn.Add_Click({ $cm = $ui.MoreBtn.ContextMenu; $cm.PlacementTarget = $ui.MoreBtn; $cm.Placement = 'Bottom'; $cm.IsOpen = $true })
$ui.OpenFolderBtn.Add_Click({ Invoke-UiSafe { Start-Process explorer.exe -ArgumentList "`"$($script:Current.Folder)`"" } })
$ui.HistOpenBtn.Add_Click({
    Invoke-UiSafe {
        $row = $ui.HistoryGrid.SelectedItem
        if ($row) { Start-Process notepad.exe -ArgumentList "`"$($row['Path'])`"" }
    }
})

$ui.LoadBtn.Add_Click({
    Invoke-UiSafe {
        $dlg = New-Object Microsoft.Win32.OpenFileDialog
        $dlg.Title = 'Open findings.json from a previous audit'
        $dlg.Filter = 'Audit results (findings.json)|findings.json|JSON files (*.json)|*.json'
        if (Test-Path $script:OutputRoot) { $dlg.InitialDirectory = $script:OutputRoot }
        if ($dlg.ShowDialog($window)) {
            Show-Results (Import-SavedResults $dlg.FileName)
            Write-UiLog "Loaded $($dlg.FileName)"
        }
    }
})

$ui.RestartAdminBtn.Add_Click({
    Invoke-UiSafe {
        if ($script:Job) { throw 'Wait for the current task to finish.' }
        $winPs = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $argsList = "-NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File `"$PSCommandPath`" -OutputRoot `"$($script:OutputRoot)`""
        try {
            Start-Process -FilePath $winPs -ArgumentList $argsList -Verb RunAs | Out-Null
            $window.Close()
        }
        catch {
            Write-UiLog 'Elevation was cancelled.'
        }
    }
})

$window.Add_Closing({
    param($s, $e)
    if ($script:Job) {
        $answer = Show-UiMessage -Text 'A task is still running. Closing now may leave it half finished. Close anyway?' -Buttons 'YesNo' -Icon 'Warning'
        if ($answer -ne 'Yes') { $e.Cancel = $true; return }
        try { $script:Job.PS.Stop() } catch { Write-Verbose "$_" }
    }
})

# ---------------------------------------------------------------------------
# Start
# ---------------------------------------------------------------------------
Update-DeviceHeader
$script:CheckSelection = Read-UiCheckSelection
Update-UiSelectionText
Update-History
$latest = $null
if (Test-Path $script:OutputRoot) {
    $latest = Get-ChildItem -LiteralPath $script:OutputRoot -Directory -Filter "$($env:COMPUTERNAME)-*" -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending |
        ForEach-Object { Join-Path $_.FullName 'findings.json' } |
        Where-Object { Test-Path -LiteralPath $_ } |
        Select-Object -First 1
}
if ($latest) {
    Invoke-UiSafe {
        Show-Results (Import-SavedResults $latest)
        [void]$ui.VerdictSub.Inlines.InsertBefore($ui.VerdictSub.Inlines.FirstInline, (New-Object Windows.Documents.Run 'Last audit shown. '))
        Write-UiLog "Loaded last results: $latest"
    }
}
else {
    Write-UiLog 'Ready. Click "Run audit" to begin.'
}

[void]$window.ShowDialog()
