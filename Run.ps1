param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $CliArgs
)

# Thin PowerShell entry point. Only what genuinely needs PowerShell lives here:
# repo-root resolution, Python/venv prerequisites, the transcript and its
# redaction, and exit-code propagation. The interactive menu, its prompts and
# validation, argument construction and launcher-log redaction moved to
# src/megabasterd_cli/launcher_menu.py, where they reuse the project's Rich
# theme and the central utils/redaction sanitizer.

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
# Launcher logs normally live under <project>/Logs. A test-only override lets
# the launcher integration tests redirect all launcher/transcript/CLI logs into
# an isolated temporary directory instead of polluting the project tree.
if (-not [string]::IsNullOrWhiteSpace($env:MEGABASTERD_LAUNCHER_LOG_DIR)) {
    $LogDir = $env:MEGABASTERD_LAUNCHER_LOG_DIR
} else {
    $LogDir = Join-Path $ProjectRoot "Logs"
}
$UserDir = Join-Path $ProjectRoot "User"
$RunId = Get-Date -Format "yyyyMMdd-HHmmss-fff"
$LauncherLogPath = Join-Path $LogDir "launcher-$RunId.log"
$CliLogPath = Join-Path $LogDir "cli-$RunId.log"
$env:MEGABASTERD_PROJECT_ROOT = $ProjectRoot
$env:MEGABASTERD_RUN_ID = $RunId
$env:MEGABASTERD_LOG_DIR = $LogDir
$env:MEGABASTERD_USER_DIR = $UserDir
$env:MEGABASTERD_CLI_LOG_FILE = $CliLogPath
# The Python launcher appends to the same launcher log this script opened.
$env:MEGABASTERD_LAUNCHER_LOG_FILE = $LauncherLogPath

$script:NoColor = [string]::Equals($env:NO_COLOR, "1", [System.StringComparison]::OrdinalIgnoreCase)
$script:LauncherExitRequested = $false
$script:IsWindowsHost = ([System.Environment]::OSVersion.Platform -eq "Win32NT")
# Resolved lazily-ish: the type only exists on .NET 7+, and only POSIX uses it.
$script:UnixOwnerOnly = if ($script:IsWindowsHost) { $null } else {
    [System.IO.UnixFileMode]::UserRead -bor [System.IO.UnixFileMode]::UserWrite
}
# Paths whose owner-only creation has already been verified this run, so the
# per-line check stays a Test-Path rather than a Get-Acl.
$script:SecuredLogs = @{}
$script:Palette = [ordered]@{
    success = "#22FF44"
    warning = "#F59E0B"
    error   = "#EF4444"
    info    = "#55D7FF"
    muted   = "#8B949E"
    path    = "#A3E635"
    install = "#06B6D4"
    python  = "#60A5FA"
}

function Get-RedactedText {
    param([string] $Text)
    # The ONE place launcher text is scrubbed. It runs on every line before it
    # is written, so a raw secret is never on disk at any instant - the old
    # design wrote a raw transcript and scrubbed it afterwards, which left the
    # secret readable for the whole run and left it forever on a hard kill.
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $sensitive = "--token|--password|--share-password|--vault-passphrase|--mfa-code|--elc-api-key"
    $Text = [regex]::Replace($Text, "(?<opt>$sensitive)(?<sep>=|\s+)(?<val>\S+)", '${opt}${sep}<redacted>')
    $Text = [regex]::Replace($Text, '(?m)(?<lead>^|\s)-p(?<sep>\s+)(?:"[^"]*"|''[^'']*''|\S+)', '${lead}-p${sep}<redacted>')
    $Text = [regex]::Replace($Text, '("(?:api_key|password|passphrase|token|mfa_code|secret)"\s*:\s*)"[^"]*"', '$1"<redacted>"')
    $Text = [regex]::Replace($Text, "\S*(?:mega\.nz/|mega\.co\.nz/|mc://|mega://)\S*", "<redacted-link>")
    return $Text
}

function Test-OwnerOnlyLogFile {
    param([string] $Path)
    try {
        if ($script:IsWindowsHost) {
            return (Get-Acl -LiteralPath $Path).AreAccessRulesProtected
        }
        return ([System.IO.File]::GetUnixFileMode($Path) -eq $script:UnixOwnerOnly)
    } catch {
        return $false
    }
}

function New-SecureLogFile {
    param([string] $Path)
    # Owner-only from the FIRST byte on BOTH platforms. This used to be Windows
    # only: Get-Acl/Set-Acl/SetAccessRuleProtection are Windows APIs, so on
    # POSIX the hardening threw, the catch swallowed it, and Add-Content then
    # created the log with the ambient umask - normally 0644, world-readable.
    # The POSIX branch below creates the file atomically with mode 0600; it is
    # never created permissively and chmod'd afterwards, because that leaves a
    # window in which anyone can read it.
    if ($script:SecuredLogs.ContainsKey($Path) -and (Test-Path -LiteralPath $Path)) {
        return
    }
    if (Test-Path -LiteralPath $Path) {
        # A file already sitting at this run's log path is not trusted: it can
        # be world-readable or a planted link. Replaced, never appended to.
        if (Test-OwnerOnlyLogFile $Path) {
            $script:SecuredLogs[$Path] = $true
            return
        }
        Remove-Item -LiteralPath $Path -Force
    }
    $options = [System.IO.FileStreamOptions]::new()
    $options.Mode = [System.IO.FileMode]::CreateNew
    $options.Access = [System.IO.FileAccess]::Write
    if (-not $script:IsWindowsHost) {
        $options.UnixCreateMode = $script:UnixOwnerOnly
    }
    ([System.IO.FileStream]::new($Path, $options)).Dispose()
    if ($script:IsWindowsHost) {
        $acl = Get-Acl -LiteralPath $Path
        $acl.SetAccessRuleProtection($true, $false)
        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $acl.SetAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $me, "FullControl", "Allow")))
        Set-Acl -LiteralPath $Path -AclObject $acl
    }
    $script:SecuredLogs[$Path] = $true
}

function Write-SecureLogLine {
    param(
        [string] $Path,
        [string] $Line
    )
    # $Line is already redacted by the caller; Add-Content on an existing file
    # appends without touching its mode or its DACL.
    if (-not (Test-Path -LiteralPath $LogDir)) {
        New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    }
    New-SecureLogFile $Path
    Add-Content -LiteralPath $Path -Value $Line -Encoding UTF8
}

function Write-RunLog {
    param(
        [string] $Level,
        [string] $Message
    )
    try {
        $safe = Get-RedactedText $Message
        $line = "{0} [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"), $Level, $safe
        Write-SecureLogLine $LauncherLogPath $line
    } catch {
        # Logging must never prevent the launcher from running.
    }
}

function Write-CliLogNote {
    param([string] $Message)
    try {
        # The CLI log gets the same treatment as the launcher log. It used to
        # get none at all - not even on Windows - although it is the file the
        # CLI itself then appends its whole run to.
        $safe = Get-RedactedText $Message
        $line = "{0} [INFO] launcher - {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"), $safe
        Write-SecureLogLine $CliLogPath $line
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

function Read-LauncherYesNo {
    # The only prompt left in PowerShell: it has to run before Python is known
    # to be usable, so it cannot live in the Python launcher.
    param(
        [string] $Message,
        [bool] $DefaultYes = $true
    )
    $defaultLabel = if ($DefaultYes) { "Y" } else { "N" }
    $prompt = "$Message (y/n) [$defaultLabel] {quit=exit}: "
    [Console]::WriteLine()
    if ($script:NoColor) {
        [Console]::Write($prompt)
    } else {
        $esc = [char]27
        Write-ColoredLine "" ""
        [Console]::Write("$(Get-AnsiColor $script:Palette['info'])${prompt}${esc}[0m")
    }
    Write-RunLog "PROMPT" $prompt
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
    if ([string]::IsNullOrWhiteSpace($trimmed)) {
        return $DefaultYes
    }
    return ($trimmed -match "^(y|yes)$")
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
    return Read-LauncherYesNo "Install dependencies now into the project environment?" $true
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

$oldPythonPath = $env:PYTHONPATH
$launchedWithoutArgs = ($CliArgs.Count -eq 0)
$exitCode = 1
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
    # Deliberately NO Start-Transcript. PowerShell's transcript opens with a
    # "Host Application:" header carrying the raw outer command line, so the
    # launcher used to write every secret passed on the command line to disk
    # in clear and scrub it only at exit - readable for the whole run, and
    # left behind permanently by Ctrl+C, a closed window, or a crash. The
    # structured log below is redacted BEFORE each line is written, so there
    # is no window in which a raw secret exists.

    Write-RunLog "INFO" "RunId=$RunId"
    Write-RunLog "INFO" "ProjectRoot=$ProjectRoot"
    Write-RunLog "INFO" "SourceRoot=$SourceRoot"
    Write-RunLog "INFO" "UserDir=$UserDir"
    Write-RunLog "INFO" "LauncherLog=$LauncherLogPath"
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
        if ($script:LauncherExitRequested) {
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

    if (-not $script:LauncherExitRequested) {
        $separator = [System.IO.Path]::PathSeparator
        if ([string]::IsNullOrWhiteSpace($oldPythonPath)) {
            $env:PYTHONPATH = $SourceRoot
        } else {
            $env:PYTHONPATH = "$SourceRoot$separator$oldPythonPath"
        }

        if ($launchedWithoutArgs) {
            Write-RunLog "INFO" "No command was supplied; opening launcher menu."
        }
        # Hand control to the Python launcher: with arguments it dispatches them
        # to the CLI, with none it opens the interactive menu. It logs the
        # redacted argument list itself, reusing the project's central sanitizer.
        # Invoked as a bare top-level statement on purpose: capturing its output
        # (into a variable, or as a function's return value) makes PowerShell
        # pipe the child's stdout, which would swallow CLI output and break the
        # menu's interactive rendering. Only $LASTEXITCODE is read afterwards.
        & $python.Command @($python.Args + @("-m", "megabasterd_cli.launcher_menu") + @($CliArgs))
        $exitCode = [int]$LASTEXITCODE
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
    # Close and scrub the transcript BEFORE the pause prompt. The pause used to
    # come first, so a failed run left an UNREDACTED transcript sitting on disk
    # for as long as nobody pressed Enter - which is exactly the window in which
    # someone reads the log to find out what went wrong.
    if ($shouldPause) {
        Write-Launcher "Command failed. Check the Logs directory for details." "error"
        [void](Read-Host "Press Enter to close")
    }
}
exit $exitCode
