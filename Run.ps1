param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $CliArgs
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

if ($null -eq $CliArgs) {
    $CliArgs = @()
}

try {
    [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
} catch {
    # Older hosts may reject changing the console encoding; the CLI still runs.
}

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$SourceRoot = Join-Path $ProjectRoot "src"
$RequirementsPath = Join-Path $ProjectRoot "requirements.txt"
$VenvDir = Join-Path $ProjectRoot ".venv"
$LogDir = Join-Path $ProjectRoot "Logs"
$UserDir = Join-Path $ProjectRoot "User"
$RunId = Get-Date -Format "yyyyMMdd-HHmmss-fff"
$LauncherLogPath = Join-Path $LogDir "launcher-$RunId.log"
$LauncherTranscriptPath = Join-Path $LogDir "launcher-transcript-$RunId.log"
$CliLogPath = Join-Path $LogDir "cli-$RunId.log"
$env:MEGABASTERD_PROJECT_ROOT = $ProjectRoot
$env:MEGABASTERD_LOG_DIR = $LogDir
$env:MEGABASTERD_USER_DIR = $UserDir
$env:MEGABASTERD_CLI_LOG_FILE = $CliLogPath

$script:NoColor = [string]::Equals($env:NO_COLOR, "1", [System.StringComparison]::OrdinalIgnoreCase)
$script:LauncherExitRequested = $false
$script:LauncherBackRequested = $false
$script:Palette = [ordered]@{
    primary     = "#55D7FF"
    secondary   = "#8B5CF6"
    accent      = "#14B8A6"
    success     = "#22FF44"
    warning     = "#F59E0B"
    error       = "#EF4444"
    info        = "#55D7FF"
    muted       = "#8B949E"
    path        = "#A3E635"
    command     = "#F472B6"
    option      = "#55D7FF"
    value       = "#E6EDF3"
    prompt      = "#E6EDF3"
    install     = "#06B6D4"
    python      = "#60A5FA"
    module      = "#C084FC"
    network     = "#34D399"
    dim         = "#64748B"
    header      = "#55D7FF"
    highlight   = "#22FF44"
    menuText    = "#E6EDF3"
    menuDefault = "#22FF44"
    menuBack    = "#FF8C00"
    menuQuit    = "#00AEEF"
    menuBrace   = "#E6EDF3"
}

function Write-RunLog {
    param(
        [string] $Level,
        [string] $Message
    )
    try {
        if (-not (Test-Path -LiteralPath $LogDir)) {
            New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
        }
        $line = "{0} [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"), $Level, $Message
        Add-Content -LiteralPath $LauncherLogPath -Value $line -Encoding UTF8
    } catch {
        # Logging must never prevent the launcher from running.
    }
}

function Write-CliLogNote {
    param([string] $Message)
    try {
        if (-not (Test-Path -LiteralPath $LogDir)) {
            New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
        }
        $line = "{0} [INFO] launcher - {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"), $Message
        Add-Content -LiteralPath $CliLogPath -Value $line -Encoding UTF8
    } catch {
        # Logging must never prevent the launcher from running.
    }
}

function Get-AnsiColor {
    param([string] $Hex)
    if ($script:NoColor) {
        return ""
    }
    $clean = $Hex.TrimStart("#")
    $r = [Convert]::ToInt32($clean.Substring(0, 2), 16)
    $g = [Convert]::ToInt32($clean.Substring(2, 2), 16)
    $b = [Convert]::ToInt32($clean.Substring(4, 2), 16)
    $esc = [char]27
    return "${esc}[38;2;${r};${g};${b}m"
}

function Get-Ansi256Color {
    param([int] $ColorCode)
    if ($script:NoColor) {
        return ""
    }
    $esc = [char]27
    return "${esc}[38;5;${ColorCode}m"
}

function Get-ConsoleWidth {
    try {
        $width = [Console]::WindowWidth
        if ($width -ge 40) {
            return $width
        }
    } catch {
        # Non-interactive hosts may not expose a console width.
    }
    return 120
}

function Write-ColoredLine {
    param(
        [string] $Message,
        [string] $Color = ""
    )
    if ($script:NoColor -or [string]::IsNullOrEmpty($Color)) {
        [Console]::WriteLine($Message)
        return
    }
    $esc = [char]27
    [Console]::WriteLine("${Color}${Message}${esc}[0m")
}

function Write-CenteredLine {
    param(
        [string] $Message,
        [string] $Color = ""
    )
    $width = Get-ConsoleWidth
    if ($Message.Length -gt $width) {
        $Message = $Message.Substring(0, $width)
    }
    $leftPadding = [Math]::Max(0, [Math]::Floor(($width - $Message.Length) / 2))
    Write-ColoredLine ((" " * $leftPadding) + $Message) $Color
}

function Write-LauncherBanner {
    $bannerColor = Get-AnsiColor "#FF3273"
    $logColor = Get-Ansi256Color 227
    $width = [Math]::Min((Get-ConsoleWidth), 120)
    $separator = "=" * $width

    Write-CenteredLine "MegaBasterd-CLI" $bannerColor
    Write-CenteredLine $separator $bannerColor
    Write-ColoredLine "Logging to: $LauncherLogPath" $logColor
    [Console]::WriteLine()

    Write-RunLog "INFO" "Displayed launcher banner."
}

function Write-Launcher {
    param(
        [string] $Message,
        [string] $Style = "info"
    )
    if ($script:NoColor -or -not $script:Palette.Contains($Style)) {
        [Console]::WriteLine($Message)
        Write-RunLog "INFO" $Message
        return
    }
    $esc = [char]27
    $prefix = Get-AnsiColor $script:Palette[$Style]
    [Console]::WriteLine("${prefix}${Message}${esc}[0m")
    Write-RunLog "INFO" $Message
}

function Write-PromptNavigationHint {
    param(
        [bool] $AllowBack = $true,
        [string] $BackToken = "0"
    )
    if ($script:NoColor) {
        if ($AllowBack) {
            [Console]::Write(" {back=$BackToken, quit=exit}: ")
        } else {
            [Console]::Write(" {quit=exit}: ")
        }
        return
    }
    $esc = [char]27
    $braceColor = Get-AnsiColor $script:Palette["menuBrace"]
    $backColor = Get-AnsiColor $script:Palette["menuBack"]
    $quitColor = Get-AnsiColor $script:Palette["menuQuit"]
    [Console]::Write(" ${braceColor}{${esc}[0m")
    if ($AllowBack) {
        [Console]::Write("${backColor}back=$BackToken${esc}[0m")
        [Console]::Write("${braceColor}, ${esc}[0m")
    }
    [Console]::Write("${quitColor}quit=exit${esc}[0m")
    [Console]::Write("${braceColor}}: ${esc}[0m")
}

function Get-LauncherDisplayPath {
    param([string] $Path)
    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $Path
    }
    try {
        $fullPath = [System.IO.Path]::GetFullPath($Path)
        $parent = (Split-Path -Parent $ProjectRoot).TrimEnd("\")
        $prefix = "$parent\"
        if ($fullPath.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            return ".\" + $fullPath.Substring($prefix.Length)
        }
    } catch {
        # Display-only path shortening must never affect the stored value.
    }
    return $Path
}

function Set-LauncherBackRequested {
    Write-RunLog "INFO" "User requested launcher back navigation."
    $script:LauncherBackRequested = $true
}

function Clear-LauncherBackRequested {
    $script:LauncherBackRequested = $false
}

function Write-LauncherPromptText {
    param([string] $Message)
    if ($script:NoColor) {
        [Console]::Write($Message)
        return
    }
    $esc = [char]27
    $promptColor = Get-AnsiColor $script:Palette["prompt"]
    $defaultColor = Get-AnsiColor $script:Palette["success"]
    $position = 0
    foreach ($match in [regex]::Matches($Message, "\[[^\]]+\]")) {
        if ($match.Index -gt $position) {
            $plain = $Message.Substring($position, $match.Index - $position)
            [Console]::Write("${promptColor}${plain}${esc}[0m")
        }
        [Console]::Write("${defaultColor}$($match.Value)${esc}[0m")
        $position = $match.Index + $match.Length
    }
    if ($position -lt $Message.Length) {
        $plain = $Message.Substring($position)
        [Console]::Write("${promptColor}${plain}${esc}[0m")
    }
}

function Read-LauncherYesNo {
    param(
        [string] $Message,
        [bool] $DefaultYes = $true,
        [bool] $AllowBack = $true
    )
    $defaultLabel = if ($DefaultYes) { "Y" } else { "N" }
    $prefix = "$Message (y/n) "
    [Console]::WriteLine()
    if ($script:NoColor) {
        [Console]::Write("$prefix[$defaultLabel]")
    } else {
        $esc = [char]27
        $defaultColor = Get-AnsiColor $script:Palette["success"]
        Write-LauncherPromptText $prefix
        [Console]::Write("${defaultColor}[$defaultLabel]${esc}[0m")
    }
    Write-PromptNavigationHint $AllowBack
    $hint = if ($AllowBack) { "{back=0, quit=exit}" } else { "{quit=exit}" }
    Write-RunLog "PROMPT" "$prefix[$defaultLabel] ${hint}: "
    $answer = [Console]::ReadLine()
    if ($null -eq $answer) {
        return $DefaultYes
    }
    $trimmed = $answer.Trim()
    if ($trimmed.Equals("exit", [System.StringComparison]::OrdinalIgnoreCase)) {
        $script:LauncherExitRequested = $true
        Write-RunLog "INFO" "User requested launcher exit from yes/no prompt."
        return $false
    }
    if ($AllowBack -and $trimmed -eq "0") {
        Set-LauncherBackRequested
        return $DefaultYes
    }
    if ([string]::IsNullOrWhiteSpace($answer)) {
        return $DefaultYes
    }
    return ($answer -match "^(y|yes)$")
}

function Read-LauncherInput {
    param(
        [string] $Message,
        [string] $Default = "",
        [bool] $AllowBack = $true,
        [string] $DisplayDefault = $null,
        [string] $BackToken = "0"
    )
    $shownDefault = if (
        $PSBoundParameters.ContainsKey("DisplayDefault") -and
        -not [string]::IsNullOrEmpty($DisplayDefault)
    ) {
        $DisplayDefault
    } else {
        $Default
    }
    $hasDefault = -not [string]::IsNullOrEmpty($Default)
    $prompt = if ($hasDefault) { "$Message [$shownDefault]" } else { $Message }
    [Console]::WriteLine()
    if ($script:NoColor) {
        [Console]::Write($prompt)
    } else {
        $esc = [char]27
        $defaultColor = Get-AnsiColor $script:Palette["success"]
        Write-LauncherPromptText $Message
        if ($hasDefault) {
            [Console]::Write(" ${defaultColor}[$shownDefault]${esc}[0m")
        }
    }
    Write-PromptNavigationHint $AllowBack $BackToken
    $hint = if ($AllowBack) { "{back=$BackToken, quit=exit}" } else { "{quit=exit}" }
    Write-RunLog "PROMPT" "$prompt ${hint}: "
    $answer = [Console]::ReadLine()
    if ($null -eq $answer) {
        return $Default
    }
    $trimmed = $answer.Trim()
    if ($trimmed.Equals("exit", [System.StringComparison]::OrdinalIgnoreCase)) {
        $script:LauncherExitRequested = $true
        Write-RunLog "INFO" "User requested launcher exit from input prompt."
        return ""
    }
    if (
        $AllowBack -and
        ($trimmed.Equals("back", [System.StringComparison]::OrdinalIgnoreCase) -or $trimmed -eq $BackToken)
    ) {
        Set-LauncherBackRequested
        return ""
    }
    if ([string]::IsNullOrWhiteSpace($answer)) {
        return $Default
    }
    return $answer
}

function Read-LauncherSecret {
    param(
        [string] $Message,
        [bool] $AllowBack = $true
    )
    $prompt = "$Message [blank to skip]"
    [Console]::WriteLine()
    if ($script:NoColor) {
        [Console]::Write($prompt)
    } else {
        Write-LauncherPromptText $prompt
    }
    Write-PromptNavigationHint $AllowBack
    $hint = if ($AllowBack) { "{back=0, quit=exit}" } else { "{quit=exit}" }
    Write-RunLog "PROMPT" "$Message (secret input) ${hint}: "

    if ([Console]::IsInputRedirected) {
        $line = [Console]::ReadLine()
        if ($null -eq $line) {
            return ""
        }
        $trimmed = $line.Trim()
        if ($trimmed.Equals("exit", [System.StringComparison]::OrdinalIgnoreCase)) {
            $script:LauncherExitRequested = $true
            Write-RunLog "INFO" "User requested launcher exit from secret prompt."
            return ""
        }
        if ($AllowBack -and $trimmed -eq "0") {
            Set-LauncherBackRequested
            return ""
        }
        return $line
    }

    $buffer = [System.Text.StringBuilder]::new()
    while ($true) {
        $key = [Console]::ReadKey($true)
        if ($key.Key -eq [ConsoleKey]::Enter) {
            [Console]::WriteLine()
            break
        }
        if ($key.Key -eq [ConsoleKey]::Backspace) {
            if ($buffer.Length -gt 0) {
                [void]$buffer.Remove($buffer.Length - 1, 1)
                [Console]::Write("`b `b")
            }
            continue
        }
        if ($key.KeyChar -eq [char]0) {
            continue
        }
        [void]$buffer.Append($key.KeyChar)
        [Console]::Write("*")
    }
    $value = $buffer.ToString()
    $trimmedValue = $value.Trim()
    if ($trimmedValue.Equals("exit", [System.StringComparison]::OrdinalIgnoreCase)) {
        $script:LauncherExitRequested = $true
        Write-RunLog "INFO" "User requested launcher exit from secret prompt."
        return ""
    }
    if ($AllowBack -and $trimmedValue -eq "0") {
        Set-LauncherBackRequested
        return ""
    }
    return $value
}

function ConvertTo-ArgumentList {
    param([string] $CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) {
        return @()
    }

    $args = [System.Collections.Generic.List[string]]::new()
    $current = [System.Text.StringBuilder]::new()
    $inSingle = $false
    $inDouble = $false
    $escaping = $false

    foreach ($ch in $CommandLine.ToCharArray()) {
        if ($escaping) {
            [void]$current.Append($ch)
            $escaping = $false
            continue
        }
        if ($ch -eq '`') {
            $escaping = $true
            continue
        }
        if ($ch -eq "'" -and -not $inDouble) {
            $inSingle = -not $inSingle
            continue
        }
        if ($ch -eq '"' -and -not $inSingle) {
            $inDouble = -not $inDouble
            continue
        }
        if ([char]::IsWhiteSpace($ch) -and -not $inSingle -and -not $inDouble) {
            if ($current.Length -gt 0) {
                $args.Add($current.ToString())
                [void]$current.Clear()
            }
            continue
        }
        [void]$current.Append($ch)
    }
    if ($escaping) {
        [void]$current.Append('`')
    }
    if ($current.Length -gt 0) {
        $args.Add($current.ToString())
    }
    return @($args)
}

function New-PythonSpec {
    param(
        [string] $Command,
        [string[]] $Arguments = @(),
        [string] $Label = $Command
    )
    [pscustomobject]@{
        Command = $Command
        Args    = @($Arguments)
        Label   = $Label
    }
}

function Invoke-Python {
    param(
        [pscustomobject] $Python,
        [string[]] $Arguments
    )
    $output = & $Python.Command @($Python.Args + $Arguments) 2>&1
    $nativeExitCode = $LASTEXITCODE
    foreach ($line in @($output)) {
        if ($null -eq $line) {
            continue
        }
        $text = $line.ToString()
        if ([string]::IsNullOrWhiteSpace($text)) {
            continue
        }
        [Console]::WriteLine($text)
        Write-RunLog "PYTHON" $text
    }
    return [int]$nativeExitCode
}

function Get-LocalVenvPython {
    $candidates = @(
        (Join-Path $VenvDir "Scripts\python.exe"),
        (Join-Path $VenvDir "bin/python")
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    return $null
}

function Test-PythonSpec {
    param([pscustomobject] $Python)
    $output = & $Python.Command @($Python.Args + @("-c", "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')")) 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $output) {
        return $false
    }
    $parts = "$output".Trim().Split(".")
    if ($parts.Count -lt 2) {
        return $false
    }
    $major = [int]$parts[0]
    $minor = [int]$parts[1]
    return ($major -gt 3 -or ($major -eq 3 -and $minor -ge 9))
}

function Find-SystemPython {
    if (-not [string]::IsNullOrWhiteSpace($env:MEGABASTERD_PYTHON)) {
        $spec = New-PythonSpec -Command $env:MEGABASTERD_PYTHON -Label $env:MEGABASTERD_PYTHON
        if (Test-PythonSpec $spec) {
            return $spec
        }
        throw "MEGABASTERD_PYTHON does not point to a usable Python 3.9+ interpreter."
    }

    $candidates = @(
        @{ Name = "py"; Args = @("-3") },
        @{ Name = "python3"; Args = @() },
        @{ Name = "python"; Args = @() }
    )
    foreach ($candidate in $candidates) {
        $cmd = Get-Command $candidate.Name -ErrorAction SilentlyContinue
        if ($null -eq $cmd) {
            continue
        }
        $spec = New-PythonSpec -Command $cmd.Source -Arguments $candidate.Args -Label $candidate.Name
        if (Test-PythonSpec $spec) {
            return $spec
        }
    }
    throw "Python 3.9+ was not found. Install Python, then run this launcher again."
}

function Get-Python {
    $venvPython = Get-LocalVenvPython
    if ($null -ne $venvPython -and [string]::IsNullOrWhiteSpace($env:MEGABASTERD_PYTHON)) {
        return New-PythonSpec -Command $venvPython -Label ".venv"
    }
    return Find-SystemPython
}

function Get-MissingModules {
    param([pscustomobject] $Python)
    $required = @(
        "click",
        "rich",
        "requests",
        "Crypto",
        "tenacity",
        "tqdm",
        "cryptography"
    )
    if ([System.Environment]::OSVersion.Platform -eq "Win32NT") {
        $required += "colorama"
    }
    $moduleCsv = $required -join ","
    $code = "import importlib.util, json; required='$moduleCsv'.split(','); print(json.dumps([m for m in required if importlib.util.find_spec(m) is None]))"
    $json = & $Python.Command @($Python.Args + @("-c", $code))
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to check Python dependencies with $($Python.Label)."
    }
    $parsed = $json | ConvertFrom-Json
    if ($null -eq $parsed) {
        return @()
    }
    return @($parsed | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
}

function Confirm-DependencyInstall {
    param([string[]] $MissingModules)
    $names = $MissingModules -join ", "
    if (-not [string]::IsNullOrWhiteSpace($env:MEGABASTERD_AUTO_INSTALL)) {
        return -not ($env:MEGABASTERD_AUTO_INSTALL -match "^(0|false|n|no)$")
    }
    Write-Launcher "Missing Python modules: $names" "warning"
    return Read-LauncherYesNo "Install dependencies now into the project environment?" $true $false
}

function New-ProjectVenv {
    $base = Find-SystemPython
    Write-Launcher "Creating local Python environment: $VenvDir" "python"
    $code = Invoke-Python $base @("-m", "venv", $VenvDir)
    if ($code -ne 0) {
        throw "Could not create the local Python environment."
    }
    $venvPython = Get-LocalVenvPython
    if ($null -eq $venvPython) {
        throw "The local Python environment was created, but python was not found inside it."
    }
    return New-PythonSpec -Command $venvPython -Label ".venv"
}

function Install-Dependencies {
    param([pscustomobject] $Python)
    if (-not (Test-Path -LiteralPath $RequirementsPath)) {
        throw "requirements.txt was not found at $RequirementsPath."
    }
    Write-Launcher "Installing dependencies from requirements.txt..." "install"
    $pipCheck = Invoke-Python $Python @("-m", "pip", "--version")
    if ($pipCheck -ne 0) {
        Write-Launcher "pip was not available in this environment; enabling it with ensurepip." "muted"
        $ensure = Invoke-Python $Python @("-m", "ensurepip", "--upgrade")
        if ($ensure -ne 0) {
            throw "Could not enable pip for the selected Python environment."
        }
    }
    $install = Invoke-Python $Python @("-m", "pip", "install", "--disable-pip-version-check", "-r", $RequirementsPath)
    if ($install -ne 0) {
        throw "Dependency installation failed."
    }
}

function Get-RedactedArgsForLog {
    param([string[]] $Arguments)
    $sensitiveOptions = @(
        "-p",
        "--password",
        "--share-password",
        "--vault-passphrase",
        "--mfa-code",
        "--elc-api-key"
    )
    $redacted = [System.Collections.Generic.List[string]]::new()
    $redactNext = $false
    foreach ($arg in @($Arguments)) {
        if ($redactNext) {
            $redacted.Add("<redacted>")
            $redactNext = $false
            continue
        }
        if ($sensitiveOptions -contains $arg) {
            $redacted.Add($arg)
            $redactNext = $true
            continue
        }
        if ($arg -match "^(--password|--share-password|--vault-passphrase|--mfa-code|--elc-api-key)=") {
            $redacted.Add(($arg -replace "=.*$", "=<redacted>"))
            continue
        }
        if ($arg -match "(mega\.nz/|mega\.co\.nz/|mc://|mega://)") {
            $redacted.Add("<redacted-link>")
            continue
        }
        $redacted.Add($arg)
    }
    return @($redacted)
}

function ConvertTo-NativeArgument {
    param([string] $Argument)
    if ($null -eq $Argument) {
        return '""'
    }
    if ($Argument -notmatch '[\s"]' -and $Argument.Length -gt 0) {
        return $Argument
    }
    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.Append('"')
    $backslashes = 0
    foreach ($char in $Argument.ToCharArray()) {
        if ($char -eq '\') {
            $backslashes++
            continue
        }
        if ($char -eq '"') {
            [void]$builder.Append("\" * (($backslashes * 2) + 1))
            [void]$builder.Append('"')
            $backslashes = 0
            continue
        }
        if ($backslashes -gt 0) {
            [void]$builder.Append("\" * $backslashes)
            $backslashes = 0
        }
        [void]$builder.Append($char)
    }
    if ($backslashes -gt 0) {
        [void]$builder.Append("\" * ($backslashes * 2))
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Join-NativeArguments {
    param([string[]] $Arguments)
    return (@($Arguments) | ForEach-Object { ConvertTo-NativeArgument $_ }) -join " "
}

function Invoke-CliCommand {
    param(
        [pscustomobject] $Python,
        [string[]] $Arguments,
        [bool] $ReturnToMenu = $true
    )
    if ($Arguments.Count -eq 0) {
        return 0
    }
    Write-RunLog "INFO" "Dispatching CLI args: $((Get-RedactedArgsForLog $Arguments) -join ' ')"
    $nativeArgs = @($Python.Args + @("-m", "megabasterd_cli") + $Arguments)
    $process = Start-Process -FilePath $Python.Command -ArgumentList (Join-NativeArguments $nativeArgs) -NoNewWindow -Wait -PassThru
    $code = $process.ExitCode
    Write-RunLog "INFO" "CLI exit code: $code"
    if ($ReturnToMenu) {
        if ($code -eq 0) {
            Write-Launcher "Command completed successfully." "success"
        } else {
            Write-Launcher "Command failed with exit code $code. Check the Logs directory for details." "error"
        }
        [void](Read-LauncherInput "Press Enter to return to the menu" "" $false)
    }
    return [int]$code
}

function Add-OptionalValue {
    param(
        [string[]] $Arguments,
        [string] $Option,
        [string] $Value
    )
    if ([string]::IsNullOrWhiteSpace($Value)) {
        return @($Arguments)
    }
    return @($Arguments + @($Option, $Value))
}

function Add-OptionalSwitch {
    param(
        [string[]] $Arguments,
        [string] $Option,
        [bool] $Enabled
    )
    if (-not $Enabled) {
        return @($Arguments)
    }
    return @($Arguments + @($Option))
}

function Add-ExtraArgs {
    param(
        [string[]] $Arguments,
        [string] $CommandName
    )
    $extra = Read-LauncherInput "Extra options for $CommandName [blank for none]"
    if ([string]::IsNullOrWhiteSpace($extra)) {
        return @($Arguments)
    }
    return @($Arguments + (ConvertTo-ArgumentList $extra))
}

function Write-MenuSection {
    param([string] $Title)
    [Console]::WriteLine()
    Write-ColoredLine "${Title}:" (Get-AnsiColor $script:Palette["header"])
}

function Write-MenuOption {
    param(
        [string] $Key,
        [string] $Label
    )
    $keyColor = Get-AnsiColor $script:Palette["option"]
    $textColor = Get-AnsiColor $script:Palette["value"]
    $defaultColor = Get-AnsiColor $script:Palette["menuDefault"]
    $suffix = if ($Key -eq "1") { " [1]" } else { "" }
    if ($script:NoColor) {
        [Console]::WriteLine(("  {0}. {1}{2}" -f $Key, $Label, $suffix))
    } else {
        $esc = [char]27
        $defaultSuffix = if ($Key -eq "1") { " ${defaultColor}[1]${esc}[0m" } else { "" }
        [Console]::WriteLine("  ${keyColor}${Key}.${esc}[0m ${textColor}${Label}${esc}[0m${defaultSuffix}")
    }
}

function Write-ColoredInline {
    param(
        [string] $Message,
        [string] $Color = ""
    )
    if ($script:NoColor -or [string]::IsNullOrEmpty($Color)) {
        [Console]::Write($Message)
        return
    }
    $esc = [char]27
    [Console]::Write("${Color}${Message}${esc}[0m")
}

function Read-MenuChoice {
    param([bool] $AllowBack = $true)
    $promptColor = Get-AnsiColor $script:Palette["prompt"]
    $defaultColor = Get-AnsiColor $script:Palette["menuDefault"]
    $braceColor = Get-AnsiColor $script:Palette["menuBrace"]
    $backColor = Get-AnsiColor $script:Palette["menuBack"]
    $quitColor = Get-AnsiColor $script:Palette["menuQuit"]

    Write-ColoredInline "Selection " $promptColor
    Write-ColoredInline "[1] " $defaultColor
    Write-ColoredInline "{" $braceColor
    if ($AllowBack) {
        Write-ColoredInline "back=0" $backColor
        Write-ColoredInline ", " $braceColor
    }
    Write-ColoredInline "quit=exit" $quitColor
    Write-ColoredInline "}: " $braceColor
    Write-RunLog "PROMPT" ($(if ($AllowBack) { "Selection [1] {back=0, quit=exit}: " } else { "Selection [1] {quit=exit}: " }))

    $answer = [Console]::ReadLine()
    if ($null -eq $answer) {
        return "exit"
    }
    if ([string]::IsNullOrWhiteSpace($answer)) {
        return "1"
    }
    return $answer.Trim().ToLowerInvariant()
}

function Test-MenuExitChoice {
    param([string] $Choice)
    if ($Choice -eq "exit") {
        $script:LauncherExitRequested = $true
        Write-RunLog "INFO" "User requested launcher exit."
        return $true
    }
    return $false
}

function Test-LauncherExitRequested {
    return $script:LauncherExitRequested
}

function Test-LauncherBackRequested {
    return $script:LauncherBackRequested
}

function Test-LauncherNavigationRequested {
    if ($script:LauncherExitRequested) {
        return $true
    }
    if ($script:LauncherBackRequested) {
        Clear-LauncherBackRequested
        return $true
    }
    return $false
}

function Move-WizardBack {
    param([ref] $Step)
    Clear-LauncherBackRequested
    if ($Step.Value -le 0) {
        return $false
    }
    $Step.Value--
    return $true
}

function Invoke-DownloadWizard {
    param([pscustomobject] $Python)
    Write-MenuSection "Download"
    $values = @{
        Source     = ""
        Output     = Join-Path $ProjectRoot "Output"
        Workers    = "8"
        Parallel   = "6"
        Limit      = "0"
        Password   = ""
        Rename     = ""
        Proxy      = ""
        SkipVerify = $false
    }
    $step = 0
    while ($step -lt 9) {
        switch ($step) {
            0 {
                $values.Source = Read-LauncherInput "MEGA link(s), or a text/DLC file path" $values.Source
                if (Test-LauncherExitRequested) { return }
                if (Test-LauncherBackRequested) {
                    if (Move-WizardBack ([ref]$step)) { continue }
                    return
                }
                if ([string]::IsNullOrWhiteSpace($values.Source)) { return }
                $step++
            }
            1 {
                $values.Output = Read-LauncherInput "Output directory" $values.Output $true (Get-LauncherDisplayPath $values.Output)
                if (Test-LauncherExitRequested) { return }
                if (Test-LauncherBackRequested) {
                    if (Move-WizardBack ([ref]$step)) { continue }
                    return
                }
                $step++
            }
            2 {
                $values.Workers = Read-LauncherInput "Workers per file" $values.Workers
                if (Test-LauncherExitRequested) { return }
                if (Test-LauncherBackRequested) {
                    if (Move-WizardBack ([ref]$step)) { continue }
                    return
                }
                $step++
            }
            3 {
                $values.Parallel = Read-LauncherInput "Parallel files (simultaneous files)" $values.Parallel
                if (Test-LauncherExitRequested) { return }
                if (Test-LauncherBackRequested) {
                    if (Move-WizardBack ([ref]$step)) { continue }
                    return
                }
                $step++
            }
            4 {
                $values.Limit = Read-LauncherInput "Speed limit KB/s (0 = unlimited)" $values.Limit $true $null "back"
                if (Test-LauncherExitRequested) { return }
                if (Test-LauncherBackRequested) {
                    if (Move-WizardBack ([ref]$step)) { continue }
                    return
                }
                $step++
            }
            5 {
                $values.Password = Read-LauncherSecret "Link password"
                if (Test-LauncherExitRequested) { return }
                if (Test-LauncherBackRequested) {
                    if (Move-WizardBack ([ref]$step)) { continue }
                    return
                }
                $step++
            }
            6 {
                $values.Rename = Read-LauncherInput "Rename single file to [blank = original name]" $values.Rename
                if (Test-LauncherExitRequested) { return }
                if (Test-LauncherBackRequested) {
                    if (Move-WizardBack ([ref]$step)) { continue }
                    return
                }
                $step++
            }
            7 {
                $values.Proxy = Read-LauncherInput "Proxy URL [blank = none/config]" $values.Proxy
                if (Test-LauncherExitRequested) { return }
                if (Test-LauncherBackRequested) {
                    if (Move-WizardBack ([ref]$step)) { continue }
                    return
                }
                $step++
            }
            8 {
                $values.SkipVerify = Read-LauncherYesNo "Skip final integrity check? (not recommended)" $values.SkipVerify
                if (Test-LauncherExitRequested) { return }
                if (Test-LauncherBackRequested) {
                    if (Move-WizardBack ([ref]$step)) { continue }
                    return
                }
                $step++
            }
        }
    }
    $args = @("download")
    if ((Test-Path -LiteralPath $values.Source) -and -not ($values.Source -match "(mega\.nz/|mega\.co\.nz/|mc://|mega://)")) {
        $args += @("-i", $values.Source)
    } else {
        $args += (ConvertTo-ArgumentList $values.Source)
    }
    $args = Add-OptionalValue $args "-o" $values.Output
    $args = Add-OptionalValue $args "-w" $values.Workers
    $args = Add-OptionalValue $args "-P" $values.Parallel
    $args = Add-OptionalValue $args "-l" $values.Limit
    $args = Add-OptionalValue $args "-p" $values.Password
    $args = Add-OptionalValue $args "--rename" $values.Rename
    $args = Add-OptionalValue $args "--proxy" $values.Proxy
    $args = Add-OptionalSwitch $args "--no-verify" $values.SkipVerify
    [void](Invoke-CliCommand $Python $args)
}

function Invoke-InfoWizard {
    param([pscustomobject] $Python)
    Write-MenuSection "Link Info"
    $values = @{
        Url      = ""
        Password = ""
    }
    $step = 0
    while ($step -lt 2) {
        switch ($step) {
            0 {
                $values.Url = Read-LauncherInput "MEGA link" $values.Url
                if (Test-LauncherExitRequested) { return }
                if (Test-LauncherBackRequested) {
                    if (Move-WizardBack ([ref]$step)) { continue }
                    return
                }
                if ([string]::IsNullOrWhiteSpace($values.Url)) { return }
                $step++
            }
            1 {
                $values.Password = Read-LauncherSecret "Link password"
                if (Test-LauncherExitRequested) { return }
                if (Test-LauncherBackRequested) {
                    if (Move-WizardBack ([ref]$step)) { continue }
                    return
                }
                $step++
            }
        }
    }
    $args = @("info", $values.Url)
    $args = Add-OptionalValue $args "--password" $values.Password
    [void](Invoke-CliCommand $Python $args)
}

function Invoke-UploadWizard {
    param([pscustomobject] $Python)
    Write-MenuSection "Upload"
    $values = @{
        Paths         = ""
        Account       = ""
        Target        = ""
        Workers       = "8"
        Parallel      = "6"
        Limit         = "0"
        KeepStructure = $true
        AutoAccount   = $false
        Share         = $false
        Vault         = ""
        Extra         = ""
    }
    $step = 0
    while ($step -lt 11) {
        switch ($step) {
            0 {
                $values.Paths = Read-LauncherInput "Local file/folder path(s)" $values.Paths
                if (Test-LauncherExitRequested) { return }
                if (Test-LauncherBackRequested) {
                    if (Move-WizardBack ([ref]$step)) { continue }
                    return
                }
                if ([string]::IsNullOrWhiteSpace($values.Paths)) { return }
                $step++
            }
            1 {
                $values.Account = Read-LauncherInput "Account email/label [blank = default]" $values.Account
                if (Test-LauncherExitRequested) { return }
                if (Test-LauncherBackRequested) {
                    if (Move-WizardBack ([ref]$step)) { continue }
                    return
                }
                $step++
            }
            2 {
                $values.Target = Read-LauncherInput "Remote target folder handle/path [blank = account root]" $values.Target
                if (Test-LauncherExitRequested) { return }
                if (Test-LauncherBackRequested) {
                    if (Move-WizardBack ([ref]$step)) { continue }
                    return
                }
                $step++
            }
            3 {
                $values.Workers = Read-LauncherInput "Workers per file" $values.Workers
                if (Test-LauncherExitRequested) { return }
                if (Test-LauncherBackRequested) {
                    if (Move-WizardBack ([ref]$step)) { continue }
                    return
                }
                $step++
            }
            4 {
                $values.Parallel = Read-LauncherInput "Parallel files (simultaneous files)" $values.Parallel
                if (Test-LauncherExitRequested) { return }
                if (Test-LauncherBackRequested) {
                    if (Move-WizardBack ([ref]$step)) { continue }
                    return
                }
                $step++
            }
            5 {
                $values.Limit = Read-LauncherInput "Upload speed limit KB/s (0 = unlimited)" $values.Limit $true $null "back"
                if (Test-LauncherExitRequested) { return }
                if (Test-LauncherBackRequested) {
                    if (Move-WizardBack ([ref]$step)) { continue }
                    return
                }
                $step++
            }
            6 {
                $values.KeepStructure = Read-LauncherYesNo "Keep folder structure?" $values.KeepStructure
                if (Test-LauncherExitRequested) { return }
                if (Test-LauncherBackRequested) {
                    if (Move-WizardBack ([ref]$step)) { continue }
                    return
                }
                $step++
            }
            7 {
                $values.AutoAccount = Read-LauncherYesNo "Auto-pick account by free space?" $values.AutoAccount
                if (Test-LauncherExitRequested) { return }
                if (Test-LauncherBackRequested) {
                    if (Move-WizardBack ([ref]$step)) { continue }
                    return
                }
                $step++
            }
            8 {
                $values.Share = Read-LauncherYesNo "Create public links after upload?" $values.Share
                if (Test-LauncherExitRequested) { return }
                if (Test-LauncherBackRequested) {
                    if (Move-WizardBack ([ref]$step)) { continue }
                    return
                }
                $step++
            }
            9 {
                $values.Vault = Read-LauncherSecret "Vault passphrase"
                if (Test-LauncherExitRequested) { return }
                if (Test-LauncherBackRequested) {
                    if (Move-WizardBack ([ref]$step)) { continue }
                    return
                }
                $step++
            }
            10 {
                $values.Extra = Read-LauncherInput "Extra options for upload [blank for none]" $values.Extra
                if (Test-LauncherExitRequested) { return }
                if (Test-LauncherBackRequested) {
                    if (Move-WizardBack ([ref]$step)) { continue }
                    return
                }
                $step++
            }
        }
    }
    $args = @("upload") + (ConvertTo-ArgumentList $values.Paths)
    $args = Add-OptionalValue $args "-a" $values.Account
    $args = Add-OptionalValue $args "--target" $values.Target
    $args = Add-OptionalValue $args "-w" $values.Workers
    $args = Add-OptionalValue $args "-P" $values.Parallel
    $args = Add-OptionalValue $args "-l" $values.Limit
    $args = Add-OptionalSwitch $args "--keep-structure" $values.KeepStructure
    $args = Add-OptionalSwitch $args "--auto-account" $values.AutoAccount
    $args = Add-OptionalSwitch $args "--share" $values.Share
    $args = Add-OptionalValue $args "--vault-passphrase" $values.Vault
    if (-not [string]::IsNullOrWhiteSpace($values.Extra)) {
        $args += (ConvertTo-ArgumentList $values.Extra)
    }
    [void](Invoke-CliCommand $Python $args)
}

function Invoke-GenericWizard {
    param(
        [pscustomobject] $Python,
        [string] $CommandName,
        [string] $Prompt
    )
    Write-MenuSection $CommandName
    $raw = Read-LauncherInput $Prompt
    if (Test-LauncherNavigationRequested) { return }
    if ([string]::IsNullOrWhiteSpace($raw)) {
        Write-Launcher "No arguments entered." "warning"
        [void](Read-LauncherInput "Press Enter to return to the menu" "" $false)
        return
    }
    $args = @($CommandName) + (ConvertTo-ArgumentList $raw)
    [void](Invoke-CliCommand $Python $args)
}

function Invoke-AccountCloudMenu {
    param([pscustomobject] $Python)
    while ($true) {
        if (Test-LauncherExitRequested) { return }
        Write-MenuSection "Account and Cloud"
        Write-MenuOption "1" "Add/login account"
        Write-MenuOption "2" "List stored accounts"
        Write-MenuOption "3" "Set default account"
        Write-MenuOption "4" "Show account quota"
        Write-MenuOption "5" "List cloud files"
        Write-MenuOption "6" "Search cloud"
        Write-MenuOption "7" "Create remote folder"
        Write-MenuOption "8" "Rename remote node"
        Write-MenuOption "9" "Move remote node"
        Write-MenuOption "10" "Remove remote node"
        Write-MenuOption "11" "Trash operations"
        Write-MenuOption "12" "Share remote node"
        Write-MenuOption "13" "Import public folder to account"
        $choice = Read-MenuChoice $true
        if (Test-MenuExitChoice $choice) { return }
        switch ($choice) {
            "1" {
                $email = Read-LauncherInput "Email"
                if (Test-LauncherExitRequested) { return }
                if (Test-LauncherBackRequested) { Clear-LauncherBackRequested; break }
                if ([string]::IsNullOrWhiteSpace($email)) { break }
                $args = @("account", "add", $email)
                $label = Read-LauncherInput "Label [blank = none]"
                if (Test-LauncherExitRequested) { return }
                if (Test-LauncherBackRequested) { Clear-LauncherBackRequested; break }
                $args = Add-OptionalValue $args "--label" $label
                $args = Add-OptionalSwitch $args "--default" (Read-LauncherYesNo "Make default account?" $true)
                if (Test-LauncherExitRequested) { return }
                if (Test-LauncherBackRequested) { Clear-LauncherBackRequested; break }
                $verify = Read-LauncherYesNo "Verify login now?" $true
                if (Test-LauncherExitRequested) { return }
                if (Test-LauncherBackRequested) { Clear-LauncherBackRequested; break }
                if (-not $verify) { $args += "--no-verify" }
                $vault = Read-LauncherSecret "Vault passphrase"
                if (Test-LauncherExitRequested) { return }
                if (Test-LauncherBackRequested) { Clear-LauncherBackRequested; break }
                $args = Add-OptionalValue $args "--vault-passphrase" $vault
                [void](Invoke-CliCommand $Python $args)
            }
            "2" { [void](Invoke-CliCommand $Python @("account", "list")) }
            "3" { Invoke-GenericWizard $Python "account" "Enter: default <email-or-label>" }
            "4" { Invoke-GenericWizard $Python "account" "Enter: info [email-or-label] [options]" }
            "5" { Invoke-GenericWizard $Python "ls" "Enter remote path/options [blank path is root; type . for root]" }
            "6" { Invoke-GenericWizard $Python "search" "Enter search query/options" }
            "7" { Invoke-GenericWizard $Python "mkdir" "Enter remote folder path/options" }
            "8" { Invoke-GenericWizard $Python "rename" "Enter node handle/path and new name/options" }
            "9" { Invoke-GenericWizard $Python "mv" "Enter source node and destination/options" }
            "10" { Invoke-GenericWizard $Python "rm" "Enter node handle/path/options" }
            "11" { Invoke-GenericWizard $Python "trash" "Enter list or empty [options]" }
            "12" { Invoke-GenericWizard $Python "share" "Enter node handle/path/options" }
            "13" { Invoke-GenericWizard $Python "import" "Enter public folder link and destination/options" }
            "0" { return }
            default { Write-Launcher "Invalid selection." "warning" }
        }
    }
}

function Invoke-QueueProxyMenu {
    param([pscustomobject] $Python)
    while ($true) {
        if (Test-LauncherExitRequested) { return }
        Write-MenuSection "Queue and Proxy"
        Write-MenuOption "1" "Queue: add download"
        Write-MenuOption "2" "Queue: add upload"
        Write-MenuOption "3" "Queue: list"
        Write-MenuOption "4" "Queue: run"
        Write-MenuOption "5" "Queue: remove"
        Write-MenuOption "6" "Queue: clear completed/canceled"
        Write-MenuOption "7" "Proxy: list"
        Write-MenuOption "8" "Proxy: add"
        Write-MenuOption "9" "Proxy: remove"
        Write-MenuOption "10" "Proxy: import from file"
        Write-MenuOption "11" "Proxy: fetch public list"
        Write-MenuOption "12" "Proxy: clear"
        Write-MenuOption "13" "Watch clipboard and queue links"
        $choice = Read-MenuChoice $true
        if (Test-MenuExitChoice $choice) { return }
        switch ($choice) {
            "1" { Invoke-GenericWizard $Python "queue" "Enter: add-download <url> [options]" }
            "2" { Invoke-GenericWizard $Python "queue" "Enter: add-upload <path> [options]" }
            "3" { [void](Invoke-CliCommand $Python @("queue", "list")) }
            "4" { Invoke-GenericWizard $Python "queue" "Enter: run [options]" }
            "5" { Invoke-GenericWizard $Python "queue" "Enter: remove <id>" }
            "6" { [void](Invoke-CliCommand $Python @("queue", "clear")) }
            "7" { [void](Invoke-CliCommand $Python @("proxy", "list")) }
            "8" { Invoke-GenericWizard $Python "proxy" "Enter: add <proxy-url> [more-url...]" }
            "9" { Invoke-GenericWizard $Python "proxy" "Enter: remove <proxy-url>" }
            "10" { Invoke-GenericWizard $Python "proxy" "Enter: import <file-path>" }
            "11" { Invoke-GenericWizard $Python "proxy" "Enter: fetch [options]" }
            "12" { [void](Invoke-CliCommand $Python @("proxy", "clear")) }
            "13" { Invoke-GenericWizard $Python "watch" "Enter watch options [blank is not accepted]" }
            "0" { return }
            default { Write-Launcher "Invalid selection." "warning" }
        }
    }
}

function Invoke-ToolsMenu {
    param([pscustomobject] $Python)
    while ($true) {
        if (Test-LauncherExitRequested) { return }
        Write-MenuSection "Tools"
        Write-MenuOption "1" "Split file"
        Write-MenuOption "2" "Merge parts"
        Write-MenuOption "3" "Encrypt local file"
        Write-MenuOption "4" "Decrypt local file"
        Write-MenuOption "5" "Resolve MegaCrypter link"
        Write-MenuOption "6" "Resolve ELC container"
        Write-MenuOption "7" "Resolve DLC container"
        Write-MenuOption "8" "Create thumbnail"
        Write-MenuOption "9" "Stream MEGA file"
        $choice = Read-MenuChoice $true
        if (Test-MenuExitChoice $choice) { return }
        switch ($choice) {
            "1" { Invoke-GenericWizard $Python "split" "Enter <source> <part-size-mb> [options]" }
            "2" { Invoke-GenericWizard $Python "merge" "Enter <any-part-file> [options]" }
            "3" { Invoke-GenericWizard $Python "crypter" "Enter: encrypt <source> <destination> [options]" }
            "4" { Invoke-GenericWizard $Python "crypter" "Enter: decrypt <source> <destination> [options]" }
            "5" { Invoke-GenericWizard $Python "crypter" "Enter: resolve <mc-url> [options]" }
            "6" { Invoke-GenericWizard $Python "crypter" "Enter: elc-resolve <mega://elc...> [options]" }
            "7" { Invoke-GenericWizard $Python "crypter" "Enter: dlc-resolve <path>" }
            "8" { Invoke-GenericWizard $Python "thumbnail" "Enter <source-image> <destination-jpg>" }
            "9" { Invoke-GenericWizard $Python "stream" "Enter <mega-link> [options]" }
            "0" { return }
            default { Write-Launcher "Invalid selection." "warning" }
        }
    }
}

function Invoke-SettingsMenu {
    param([pscustomobject] $Python)
    while ($true) {
        if (Test-LauncherExitRequested) { return }
        Write-MenuSection "Settings"
        Write-ColoredLine "User data: $UserDir" (Get-AnsiColor $script:Palette["path"])
        Write-MenuOption "1" "Show current configuration"
        Write-MenuOption "2" "Set default download folder"
        Write-MenuOption "3" "Set download workers"
        Write-MenuOption "4" "Set speed limit"
        Write-MenuOption "5" "Set ELC API credentials"
        Write-MenuOption "6" "Add/login MEGA account"
        Write-MenuOption "7" "List accounts"
        Write-MenuOption "8" "Set default account"
        Write-MenuOption "9" "Show config path"
        Write-MenuOption "10" "Reset config"
        $choice = Read-MenuChoice $true
        if (Test-MenuExitChoice $choice) { return }
        switch ($choice) {
            "1" { [void](Invoke-CliCommand $Python @("config", "show")) }
            "2" {
                $path = Read-LauncherInput "Default download folder" (Join-Path $ProjectRoot "Output")
                if (Test-LauncherExitRequested) { return }
                if (Test-LauncherBackRequested) { Clear-LauncherBackRequested; break }
                if ($path) { [void](Invoke-CliCommand $Python @("config", "set", "download_path", $path)) }
            }
            "3" {
                $workers = Read-LauncherInput "Download workers" "8"
                if (Test-LauncherExitRequested) { return }
                if (Test-LauncherBackRequested) { Clear-LauncherBackRequested; break }
                if ($workers) { [void](Invoke-CliCommand $Python @("config", "set", "max_workers", $workers)) }
            }
            "4" {
                $limit = Read-LauncherInput "Speed limit KB/s (0 = unlimited)" "0" $true $null "back"
                if (Test-LauncherExitRequested) { return }
                if (Test-LauncherBackRequested) { Clear-LauncherBackRequested; break }
                if ($limit) { [void](Invoke-CliCommand $Python @("config", "set", "speed_limit_kbps", $limit)) }
            }
            "5" {
                $host = Read-LauncherInput "ELC host"
                if (Test-LauncherExitRequested) { return }
                if (Test-LauncherBackRequested) { Clear-LauncherBackRequested; break }
                $user = Read-LauncherInput "ELC user"
                if (Test-LauncherExitRequested) { return }
                if (Test-LauncherBackRequested) { Clear-LauncherBackRequested; break }
                $apiKey = Read-LauncherSecret "ELC API key"
                if (Test-LauncherExitRequested) { return }
                if (Test-LauncherBackRequested) { Clear-LauncherBackRequested; break }
                if ($host -and $user -and $apiKey) {
                    $payload = @{ $host = @{ user = $user; api_key = $apiKey } } | ConvertTo-Json -Compress
                    [void](Invoke-CliCommand $Python @("config", "set", "elc_accounts", $payload))
                }
            }
            "6" {
                $email = Read-LauncherInput "Email"
                if (Test-LauncherExitRequested) { return }
                if (Test-LauncherBackRequested) { Clear-LauncherBackRequested; break }
                if ([string]::IsNullOrWhiteSpace($email)) { break }
                $args = @("account", "add", $email)
                $label = Read-LauncherInput "Label [blank = none]"
                if (Test-LauncherExitRequested) { return }
                if (Test-LauncherBackRequested) { Clear-LauncherBackRequested; break }
                $args = Add-OptionalValue $args "--label" $label
                $args = Add-OptionalSwitch $args "--default" (Read-LauncherYesNo "Make default account?" $true)
                if (Test-LauncherExitRequested) { return }
                if (Test-LauncherBackRequested) { Clear-LauncherBackRequested; break }
                $vault = Read-LauncherSecret "Vault passphrase"
                if (Test-LauncherExitRequested) { return }
                if (Test-LauncherBackRequested) { Clear-LauncherBackRequested; break }
                $args = Add-OptionalValue $args "--vault-passphrase" $vault
                [void](Invoke-CliCommand $Python $args)
            }
            "7" { [void](Invoke-CliCommand $Python @("account", "list")) }
            "8" { Invoke-GenericWizard $Python "account" "Enter: default <email-or-label>" }
            "9" { [void](Invoke-CliCommand $Python @("config", "path")) }
            "10" { [void](Invoke-CliCommand $Python @("config", "reset")) }
            "0" { return }
            default { Write-Launcher "Invalid selection." "warning" }
        }
    }
}

function Invoke-LauncherMenu {
    param([pscustomobject] $Python)
    while ($true) {
        if ($script:LauncherExitRequested) {
            Write-RunLog "INFO" "User exited launcher menu."
            return 0
        }
        Write-MenuSection "MegaBasterd-CLI Main menu"
        Write-MenuOption "1" "Download MEGA link/file"
        Write-MenuOption "2" "Show link info"
        Write-MenuOption "3" "Upload file/folder"
        Write-MenuOption "4" "Account and cloud operations"
        Write-MenuOption "5" "Queue and proxy"
        Write-MenuOption "6" "Tools"
        Write-MenuOption "7" "Settings"
        Write-MenuOption "8" "Advanced CLI command"
        $choice = Read-MenuChoice $false
        if (Test-MenuExitChoice $choice) {
            Write-RunLog "INFO" "User exited launcher menu."
            return 0
        }
        switch ($choice) {
            "1" { Invoke-DownloadWizard $Python }
            "2" { Invoke-InfoWizard $Python }
            "3" { Invoke-UploadWizard $Python }
            "4" { Invoke-AccountCloudMenu $Python }
            "5" { Invoke-QueueProxyMenu $Python }
            "6" { Invoke-ToolsMenu $Python }
            "7" { Invoke-SettingsMenu $Python }
            "8" {
                $raw = Read-LauncherInput "Enter CLI arguments"
                if (Test-LauncherExitRequested) { return 0 }
                if (Test-LauncherBackRequested) { Clear-LauncherBackRequested; continue }
                if ($raw) { [void](Invoke-CliCommand $Python (ConvertTo-ArgumentList $raw)) }
            }
            "0" {
                Write-RunLog "INFO" "User exited launcher menu."
                return 0
            }
            default { Write-Launcher "Invalid selection." "warning" }
        }
    }
}

$oldPythonPath = $env:PYTHONPATH
$launchedWithoutArgs = ($CliArgs.Count -eq 0)
$exitCode = 1
$transcriptStarted = $false
try {
    if (-not (Test-Path -LiteralPath $LogDir)) {
        New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    }
    if (-not (Test-Path -LiteralPath $UserDir)) {
        New-Item -ItemType Directory -Path $UserDir -Force | Out-Null
    }
    foreach ($userSubdir in @(
        (Join-Path $UserDir "Config"),
        (Join-Path $UserDir "Data"),
        (Join-Path $UserDir "Data\sessions"),
        (Join-Path $UserDir "Logs")
    )) {
        if (-not (Test-Path -LiteralPath $userSubdir)) {
            New-Item -ItemType Directory -Path $userSubdir -Force | Out-Null
        }
    }
    try {
        Start-Transcript -LiteralPath $LauncherTranscriptPath -Append | Out-Null
        $transcriptStarted = $true
    } catch {
        Write-RunLog "WARN" "Start-Transcript failed: $($_.Exception.Message)"
    }

    Write-RunLog "INFO" "RunId=$RunId"
    Write-RunLog "INFO" "ProjectRoot=$ProjectRoot"
    Write-RunLog "INFO" "SourceRoot=$SourceRoot"
    Write-RunLog "INFO" "UserDir=$UserDir"
    Write-RunLog "INFO" "LauncherLog=$LauncherLogPath"
    Write-RunLog "INFO" "LauncherTranscript=$LauncherTranscriptPath"
    Write-RunLog "INFO" "CliLog=$CliLogPath"
    Write-CliLogNote "CLI log prepared by launcher. Some commands such as --help may exit before Python logging is initialized."

    if (-not (Test-Path -LiteralPath $SourceRoot)) {
        throw "Source directory was not found: $SourceRoot"
    }

    Write-LauncherBanner
    Write-Launcher "Checking prerequisites..." "info"

    $python = Get-Python
    Write-RunLog "INFO" "Python=$($python.Command) Args=$($python.Args -join ' ') Label=$($python.Label)"

    $missing = @(Get-MissingModules $python)
    if ($missing.Count -gt 0) {
        $installConfirmed = Confirm-DependencyInstall $missing
        if (Test-LauncherExitRequested) {
            $exitCode = 0
        } elseif (-not $installConfirmed) {
            Write-Launcher "Dependency installation was cancelled." "error"
            throw "Dependency installation was cancelled."
        } else {
            $explicitPython = -not [string]::IsNullOrWhiteSpace($env:MEGABASTERD_PYTHON)
            $localVenv = Get-LocalVenvPython
            if (-not $explicitPython -and $null -eq $localVenv) {
                $python = New-ProjectVenv
            }
            Install-Dependencies $python
            $missing = @(Get-MissingModules $python)
            if ($missing.Count -gt 0) {
                throw "Dependencies are still missing after installation: $($missing -join ', ')"
            }
            Write-Launcher "Dependencies are ready." "success"
        }
    }

    if (-not (Test-LauncherExitRequested)) {
        $separator = [System.IO.Path]::PathSeparator
        if ([string]::IsNullOrWhiteSpace($oldPythonPath)) {
            $env:PYTHONPATH = $SourceRoot
        } else {
            $env:PYTHONPATH = "$SourceRoot$separator$oldPythonPath"
        }

        if ($launchedWithoutArgs) {
            Write-RunLog "INFO" "No command was supplied; opening launcher menu."
            $exitCode = Invoke-LauncherMenu $python
        } else {
            $exitCode = Invoke-CliCommand $python $CliArgs $false
        }
    }
} catch {
    $exitCode = 1
    Write-Launcher "Launcher error: $($_.Exception.Message)" "error"
    Write-RunLog "ERROR" $_.Exception.ToString()
} finally {
    $env:PYTHONPATH = $oldPythonPath
    $shouldPause = (
        ((-not $launchedWithoutArgs) -and $exitCode -ne 0) -and
        -not ($env:MEGABASTERD_NO_PAUSE -match "^(1|true|yes)$")
    )
    if ($shouldPause) {
        Write-Launcher "Command failed. Check the Logs directory for details." "error"
        [void](Read-Host "Press Enter to close")
    }
    if ($transcriptStarted) {
        try {
            Stop-Transcript | Out-Null
        } catch {
            Write-RunLog "WARN" "Stop-Transcript failed: $($_.Exception.Message)"
        }
    }
}
exit $exitCode
