# 从当前用户的受信任根证书中移除 teletalk MITM CA。
$ErrorActionPreference = 'Stop'
$caPath = Join-Path $PSScriptRoot 'certs\ca.crt'
if (-not (Test-Path $caPath)) { Write-Error "找不到 CA 证书"; exit 1 }

$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $caPath
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store 'Root', 'CurrentUser'
$store.Open('ReadWrite')
$found = $store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
if ($found) { $store.Remove($found); Write-Host "已移除: $($cert.Thumbprint)" }
else { Write-Host "证书未安装，无需移除" }
$store.Close()
