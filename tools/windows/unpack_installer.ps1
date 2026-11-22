#Requires -Version 5.1
<#
.SYNOPSIS
    把 fbapp-speed.exe（Inno Setup）静默解包到隔离目录，并输出文件清单。

.DESCRIPTION
    只做两件事：解包 + 清单。不启动主程序、不改系统代理。
    注意：安装会注册服务 uanetfbclientappapexHelperService 并安装 TUN 组件；
    分析完请用 -Uninstall 或目标目录里的 unins000.exe 还原。

.EXAMPLE
    .\unpack_installer.ps1 -Installer C:\AID\fbapp-speed.exe -Dest C:\rev\apex-7.3.1

.EXAMPLE
    .\unpack_installer.ps1 -Installer C:\AID\fbapp-speed.exe -Dest C:\rev\apex-7.3.1 -Uninstall
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Installer,
    [Parameter(Mandatory = $true)][string]$Dest,
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $Installer)) { throw "安装包不存在: $Installer" }
$Installer = (Resolve-Path $Installer).Path

if ($Uninstall) {
    $unins = Join-Path $Dest 'unins000.exe'
    if (-not (Test-Path $unins)) { throw "找不到卸载器: $unins" }
    Write-Host "[*] 卸载 $Dest ..."
    Start-Process $unins -Wait -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART'
    $svc = Get-Service -Name 'uanetfbclientappapexHelperService' -ErrorAction SilentlyContinue
    if ($svc) { Write-Warning "服务仍在: $($svc.Name) $($svc.Status)" } else { Write-Host "[+] 服务已移除" }
    return
}

# 版本信息（可从安装包本身读出，不必先装）
$vi = (Get-Item $Installer).VersionInfo
$hash = (Get-FileHash $Installer -Algorithm SHA256).Hash
Write-Host "[i] 安装包: $Installer"
Write-Host "[i] 大小  : $((Get-Item $Installer).Length) B"
Write-Host "[i] SHA256: $hash"
Write-Host "[i] 版本  : $($vi.ProductVersion) / $($vi.FileDescription)"

New-Item -ItemType Directory -Force -Path $Dest | Out-Null
$log = Join-Path $Dest 'install.log'

Write-Host "[*] 静默解包 -> $Dest"
$p = Start-Process -FilePath $Installer -Wait -PassThru -ArgumentList @(
    '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/NOCANCEL', '/SP-',
    "/DIR=`"$Dest`"", "/LOG=`"$log`""
)
Write-Host "[i] 安装器退出码: $($p.ExitCode)"

# 主程序若被自动拉起，先收掉（分析期间不联网）
Get-Process -Name Apex -ErrorAction SilentlyContinue | Stop-Process -Force

$files = Get-ChildItem $Dest -File -Recurse | Sort-Object Length -Descending
$report = [pscustomobject]@{
    installer    = $Installer
    installer_sha256 = $hash
    product      = $vi.ProductName
    product_version = $vi.ProductVersion
    dest         = $Dest
    file_count   = $files.Count
    total_bytes  = ($files | Measure-Object Length -Sum).Sum
    files        = $files | ForEach-Object {
        [pscustomobject]@{
            path   = $_.FullName.Substring($Dest.Length + 1)
            size   = $_.Length
            sha256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
        }
    }
}
$out = Join-Path $Dest 'inventory.json'
$report | ConvertTo-Json -Depth 4 | Set-Content -Path $out -Encoding UTF8

Write-Host "[+] 文件数: $($report.file_count)  合计: $($report.total_bytes) B"
Write-Host "[+] 清单: $out"
$manifest = Join-Path $Dest 'apex-windows-components.json'
if (Test-Path $manifest) {
    $m = Get-Content $manifest -Raw | ConvertFrom-Json
    $core = Join-Path $Dest 'ApexCore.exe'
    $coreHash = if (Test-Path $core) { (Get-FileHash $core -Algorithm SHA256).Hash.ToLower() } else { $null }
    Write-Host "[i] 组件清单 schema=$($m.schema) files=$($m.files.Count) service=$($m.service_name)"
    Write-Host "[i] core_sha256 清单=$($m.core_sha256)"
    Write-Host "[i] core_sha256 实测=$coreHash  匹配=$($coreHash -eq $m.core_sha256)"
}
Write-Host ""
Write-Host "下一步：python tools\windows\verify_build.py `"$Dest`""
Write-Host "还原  ：$Dest\unins000.exe /VERYSILENT"
