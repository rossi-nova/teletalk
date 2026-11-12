# 安装 Ghidra 并分析 SDK
# 用法：powershell -ExecutionPolicy Bypass -File tools/ghidra/setup.ps1

$ErrorActionPreference = 'Stop'

$Zip    = "$env:USERPROFILE\Downloads\ghidra_11.4.2_PUBLIC.zip"
$Extract= "C:\Tools"
$Ghidra = Join-Path $Extract "ghidra_11.4.2_PUBLIC"
$SDK    = "C:\Program Files (x86)\DingDing\main\current_new\SecurityGuardSDK64.dll"
$Root   = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$Proj   = Join-Path $Root ".ghidra\proj"
$Out    = Join-Path $Root ".ghidra\out"

if (-not (Test-Path $Zip)) { throw "缺少安装包：$Zip" }

if (-not (Test-Path $Ghidra)) {
    Write-Host "解压 Ghidra 到 $Extract ..."
    New-Item -ItemType Directory -Force -Path $Extract | Out-Null
    Expand-Archive -Path $Zip -DestinationPath $Extract -Force
    Write-Host "解压完成"
} else {
    Write-Host "Ghidra 已存在：$Ghidra"
}

# Java 检查
$java = Get-Command java -ErrorAction SilentlyContinue
if (-not $java) { throw "未找到 java，请先安装 JDK 21+" }
Write-Host "Java: $($java.Source)"

# 校验 headless 脚本存在
$hl = Join-Path $Ghidra "support\analyzeHeadless.bat"
if (-not (Test-Path $hl)) { throw "缺少 $hl" }

New-Item -ItemType Directory -Force -Path $Proj, $Out | Out-Null

Write-Host ""
Write-Host "下一步（首次导入，5–20 分钟）："
Write-Host ""
Write-Host "  & `"$hl`" `"$Proj`" Teletalk -import `"$SDK`" -overwrite"
Write-Host ""
Write-Host "然后导出反编译："
Write-Host ""
Write-Host "  & `"$hl`" `"$Proj`" Teletalk -process SecurityGuardSDK64.dll -noanalysis -scriptPath `"$Root\tools\ghidra`" -postScript TeletalkSdk.java `"$Out`""
