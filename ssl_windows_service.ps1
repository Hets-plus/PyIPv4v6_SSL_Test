<#
PyIPv4v6_SSL_Test - SSL/TLS 测试工具
Windows 服务管理脚本
Copyright (c) 2026 by hets

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

#>

param(
    [ValidateSet('install','uninstall','start','stop','status','run')]
    [string]$Action = 'install',
    [string]$ServiceName = 'PyIPv6_SSL_Tool',
    [string]$DisplayName = 'PyIPv6 SSL Tool',
    [ValidateSet('client','server','both')]
    [string]$Mode = 'server',
    [string]$Config = 'tls_config.json',
    [string]$Python = 'python',
    [string]$LogDir = 'logs'
)

$ErrorActionPreference = 'Stop'

function Test-Admin {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($current)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-Admin {
    if (-not (Test-Admin)) {
        throw '需要管理员权限运行（请用“以管理员身份运行PowerShell”）。'
    }
}

function Get-Root {
    try {
        return Split-Path -Parent $MyInvocation.MyCommand.Path
    } catch {
        return (Get-Location).Path
    }
}

function Ensure-LogDir([string]$root, [string]$logDirParam) {
    if ([System.IO.Path]::IsPathRooted($logDirParam)) {
        $logDir = $logDirParam
    } else {
        $logDir = Join-Path $root $logDirParam
    }
    New-Item -ItemType Directory -Force -Path $logDir | Out-Null
    return $logDir
}

function Append-Log([string]$logFile, [string]$text) {
    try {
        $stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Add-Content -Path $logFile -Value ("[$stamp] " + $text)
    } catch {
    }
}

function Invoke-Python([string]$root, [string]$python, [string]$logFile, [Parameter(ValueFromRemainingArguments=$true)][string[]]$Args) {
    $cmd = @($python, "main.py") + $Args
    Append-Log $logFile ("run: " + ($cmd -join ' '))
    $out = & $python "main.py" @Args 2>&1
    $code = $LASTEXITCODE
    if ($out) {
        Append-Log $logFile ($out | Out-String)
    }
    if ($code -ne 0) {
        $outText = ""
        try {
            if ($out) {
                $outText = ($out | Out-String)
                if ($outText.Length -gt 4000) {
                    $outText = $outText.Substring($outText.Length - 4000)
                }
            }
        } catch {
        }
        try {
            Write-Host ("log file: " + $logFile)
        } catch {
        }
        if ($outText) {
            try {
                Write-Host "--- python output (tail) ---"
                Write-Host $outText
            } catch {
            }
        }
        if ($outText) {
            throw ("command failed (" + $code + "): " + ($cmd -join ' ') + "`n--- python output (tail) ---`n" + $outText)
        }
        throw ("command failed (" + $code + "): " + ($cmd -join ' '))
    }
}

function Install-Service([string]$root, [string]$serviceName, [string]$displayName, [string]$mode, [string]$config, [string]$python, [string]$logDirParam) {
    Ensure-Admin

    $logDir = Ensure-LogDir $root $logDirParam
    $installLog = Join-Path $logDir 'tls_windows_service_install.log'

    Set-Location $root
    Append-Log $installLog "install service: $serviceName"
    Invoke-Python $root $python $installLog --service install --name $serviceName --display $displayName --mode $mode --config $config --startup auto --log-dir $logDir
}

function Uninstall-Service([string]$serviceName, [string]$logDirParam) {
    Ensure-Admin
    $root = Get-Root
    $logDir = Ensure-LogDir $root $logDirParam
    $installLog = Join-Path $logDir 'tls_windows_service_install.log'
    Set-Location $root
    Invoke-Python $root $Python $installLog --service uninstall --name $serviceName
}

function Start-ServiceSafe([string]$serviceName, [string]$logDirParam) {
    Ensure-Admin
    $root = Get-Root
    $logDir = Ensure-LogDir $root $logDirParam
    $installLog = Join-Path $logDir 'tls_windows_service_install.log'
    Set-Location $root
    Invoke-Python $root $Python $installLog --service start --name $serviceName
}

function Stop-ServiceSafe([string]$serviceName, [string]$logDirParam) {
    Ensure-Admin
    $root = Get-Root
    $logDir = Ensure-LogDir $root $logDirParam
    $installLog = Join-Path $logDir 'tls_windows_service_install.log'
    Set-Location $root
    Invoke-Python $root $Python $installLog --service stop --name $serviceName
}

function Status-Service([string]$serviceName, [string]$logDirParam) {
    $root = Get-Root
    $logDir = Ensure-LogDir $root $logDirParam
    $installLog = Join-Path $logDir 'tls_windows_service_install.log'
    Set-Location $root
    Invoke-Python $root $Python $installLog --service status --name $serviceName
}

function Run-Service([string]$root, [string]$mode, [string]$config, [string]$python, [string]$logDirParam) {
    $logDir = Ensure-LogDir $root $logDirParam
    $watchdog = Join-Path $logDir 'tls_service_watchdog.log'
    $outFile = Join-Path $logDir 'tls_service_stdout.log'
    $errFile = Join-Path $logDir 'tls_service_stderr.log'

    try {
        Append-Log $watchdog "run headless: $python main.py --headless $mode $config --log-dir $logDir"
        $p = Start-Process -FilePath $python -ArgumentList @('main.py', '--headless', $mode, $config, '--log-dir', $logDir) -WorkingDirectory $root -PassThru -RedirectStandardOutput $outFile -RedirectStandardError $errFile
        $p.WaitForExit()
        Append-Log $watchdog "main.py exit code: $($p.ExitCode)"
        exit [int]$p.ExitCode
    } catch {
        Append-Log $watchdog ("runner exception: " + $_.Exception.Message)
        exit 1
    }
}

$rootDir = Get-Root

switch ($Action) {
    'install' { Install-Service -root $rootDir -serviceName $ServiceName -displayName $DisplayName -mode $Mode -config $Config -python $Python -logDirParam $LogDir }
    'uninstall' { Uninstall-Service -serviceName $ServiceName -logDirParam $LogDir }
    'start' { Start-ServiceSafe -serviceName $ServiceName -logDirParam $LogDir }
    'stop' { Stop-ServiceSafe -serviceName $ServiceName -logDirParam $LogDir }
    'status' { Status-Service -serviceName $ServiceName -logDirParam $LogDir }
    'run' { Run-Service -root $rootDir -mode $Mode -config $Config -python $Python -logDirParam $LogDir }
}
