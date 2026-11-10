# 把 teletalk MITM 根证书装进当前用户的「受信任的根证书颁发机构」。
# 只影响当前用户（Cert:\CurrentUser\Root），不需要管理员权限，可用 uninstall-ca.ps1 移除。
# 用法： powershell -ExecutionPolicy Bypass -File install-ca.ps1

$ErrorActionPreference = 'Stop'
$caPath = Join-Path $PSScriptRoot 'certs\ca.crt'

if (-not (Test-Path $caPath)) {
    Write-Error "找不到 CA 证书: $caPath"
    exit 1
}

$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $caPath
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store 'Root', 'CurrentUser'
$store.Open('ReadWrite')

$existing = $store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
if ($existing) {
    Write-Host "证书已存在，指纹: $($cert.Thumbprint)"
} else {
    $store.Add($cert)
    Write-Host "已安装到 CurrentUser\Root，指纹: $($cert.Thumbprint)"
}
$store.Close()
Write-Host "完成后记得用 uninstall-ca.ps1 移除。"
