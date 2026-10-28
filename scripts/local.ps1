<#
.SYNOPSIS
    local.ps1 — Windows 一键：导入证书 → 生成配置 → 拉取 v1/v2/both → 汇总

.DESCRIPTION
    用法：
      .\scripts\local.ps1 init --certs <客户端证书目录>   # 导入证书 + 写配置
      .\scripts\local.ps1 run                             # 拉 v1 + v2 + both
      .\scripts\local.ps1 run --source v1                 # 只拉一条
      .\scripts\local.ps1 all --certs <目录>              # init + run
      .\scripts\local.ps1 check                           # 只检查环境

    凭据：优先读环境变量 APEX_EMAIL / APEX_PASSWORD，否则交互输入（不回显）。
    目录：默认  $HOME/.apex-local\{certs,out,config}（在仓库之外，不会误提交）

.EXAMPLE
    .\scripts\local.ps1 all --certs "C:\Program Files\Apex\certs"
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('init', 'run', 'all', 'check', '')]
    [string]$Command = '',

    [string]$Certs,
    [ValidateSet('v1', 'v2', 'both', 'all')]
    [string]$Source = 'all'
)

$ErrorActionPreference = 'Stop'

$Root   = Split-Path -Parent $PSScriptRoot
$Base   = if ($env:APEX_LOCAL_DIR) { $env:APEX_LOCAL_DIR } else { Join-Path $HOME '.apex-local' }
$CertDir = Join-Path $Base 'certs'
$OutDir  = Join-Path $Base 'out'
$Conf    = Join-Path $Base 'config'

$ApiBase  = if ($env:API_BASE)  { $env:API_BASE }  else { 'https://fbaxapi.apiv2.a047.com' }
$SubBase  = if ($env:SUB_BASE)  { $env:SUB_BASE }  else { 'https://fbaxsub.web.ak005.com' }
$MinNodes = if ($env:MIN_NODES) { $env:MIN_NODES } else { '20' }

function Write-Ok   { param($m) Write-Host $m -ForegroundColor Green }
function Write-Warn { param($m) Write-Host $m -ForegroundColor Yellow }
function Write-Err  { param($m) Write-Host "错误：$m" -ForegroundColor Red }
function Die        { param($m) Write-Err $m; exit 1 }

function Show-Usage {
    Get-Help $PSCommandPath -Detailed | Out-String | Write-Host
    exit 0
}

# ---------------------------------------------------------------- check
function Invoke-Check {
    $py = Get-PyCmd
    & $py "$Root\scripts\_check_env.py"
    if ($LASTEXITCODE -ne 0) { Die '环境检查未通过' }
    Write-Ok '环境检查通过'
}

# ---------------------------------------------------------------- init
function Import-Certs {
    param([string]$Src)
    if (-not (Test-Path $Src)) { Die "证书目录不存在：$Src" }

    New-Item -ItemType Directory -Path $CertDir -Force | Out-Null
    $n = 0

    # 1) 标准命名
    foreach ($f in @('api.crt', 'api.key', 'sub.crt', 'sub.key')) {
        $p = Join-Path $Src $f
        if ((Test-Path $p) -and -not (Test-Path (Join-Path $CertDir $f))) {
            Copy-Item $p (Join-Path $CertDir $f); $n++
        }
    }

    # 2) 客户端原始命名 profile5_<purpose>_client.<ext>.pem
    foreach ($purpose in @(@('api', 'api'), @('subscription', 'sub'))) {
        foreach ($ext in @('crt', 'key')) {
            $hits = Get-ChildItem -Path $Src -Filter "profile5_$($purpose[0])_client*.$ext.pem" -File -ErrorAction SilentlyContinue
            if ($hits) {
                $dst = Join-Path $CertDir "$($purpose[1]).$ext"
                if (-not (Test-Path $dst)) { Copy-Item $hits[0].FullName $dst; $n++ }
            }
        }
    }

    # 收紧权限（仅当前用户）
    try {
        $acl = Get-Acl $CertDir
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($f in (Get-ChildItem $CertDir -File)) {
            $a = Get-Acl $f.FullName
            $a.SetAccessRuleProtection($true, $false)
            $a.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                "$env:USERDOMAIN\$env:USERNAME", 'FullControl', 'Allow')))
            Set-Acl $f.FullName $a
        }
    } catch { Write-Warn "权限收紧失败（不影响使用）：$($_.Exception.Message)" }

    Write-Ok "导入 $n 个证书文件 → $CertDir"
}

function Invoke-Init {
    New-Item -ItemType Directory -Path $CertDir, $OutDir -Force | Out-Null
    if ($Certs) { Import-Certs $Certs }

    if (-not (Test-Path (Join-Path $CertDir 'api.crt'))) { Write-Warn "缺 api.crt（v1 需要 api 证书）" }
    if (-not (Test-Path (Join-Path $CertDir 'sub.crt'))) { Write-Warn "缺 sub.crt（v2 需要 subscription 证书）" }

    $email = $env:APEX_EMAIL
    $pass  = $env:APEX_PASSWORD
    if (-not $email) { $email = Read-Host '账号邮箱' }
    if (-not $pass) {
        $sec = Read-Host '密码（不回显）' -AsSecureString
        $pass = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
    }
    if (-not $email -or -not $pass) { Die '账号或密码为空' }

    $lines = @(
        "API_BASE=$ApiBase"
        "SUB_BASE=$SubBase"
        "APEX_EMAIL=$email"
        "APEX_PASSWORD=$pass"
        "CERT_DIR=$($CertDir -replace '\\', '/')"
        "MIN_NODES=$MinNodes"
        "SOURCE=v2"
    )
    Set-Content -Path $Conf -Value $lines -Encoding ASCII
    Write-Ok "配置已写入 $Conf"
}

# ---------------------------------------------------------------- run
function Get-PyCmd {
    $c = Get-Command python -ErrorAction SilentlyContinue
    if (-not $c) { $c = Get-Command python3 -ErrorAction SilentlyContinue }
    if (-not $c) { Die '找不到 python（请先安装并加入 PATH）' }
    return $c.Source
}

function Invoke-RunOne {
    param([string]$S)
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
    Write-Host "`n── $S ─────────────────────────────" -ForegroundColor Cyan
    & (Get-PyCmd) (Join-Path $Root 'src\apex_fetch.py') --config $Conf --source $S --out (Join-Path $OutDir "$S.yaml")
    if ($LASTEXITCODE -ne 0) { Write-Warn "$S 失败（继续）" }
}

function Invoke-Run {
    if (-not (Test-Path $Conf)) { Die "没有配置文件，先跑：$PSCommandPath init --certs <证书目录>" }
    switch ($Source) {
        'all' { foreach ($s in @('v2', 'v1', 'both')) { Invoke-RunOne $s } }
        default { Invoke-RunOne $Source }
    }

    Write-Host "`n── 汇总 ────────────────────────────" -ForegroundColor Cyan
    & (Get-PyCmd) "$Root\scripts\_summary.py" $OutDir
}

# ---------------------------------------------------------------- main
switch ($Command) {
    'check' { Invoke-Check }
    'init'  { Invoke-Check; Invoke-Init }
    'run'   { Invoke-Run }
    'all'   { Invoke-Check; Invoke-Init; Invoke-Run }
    default { Show-Usage }
}
