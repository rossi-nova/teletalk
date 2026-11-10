# 设置 / 还原当前用户的系统 HTTP 代理（WinINET，即钉钉读取的那一处）。
# 用法：
#   powershell -ExecutionPolicy Bypass -File setup-proxy.ps1 -Enable -Port 8888
#   powershell -ExecutionPolicy Bypass -File setup-proxy.ps1 -Disable
param(
    [switch]$Enable,
    [switch]$Disable,
    [int]$Port = 8888
)
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'

if ($Enable) {
    $backup = Get-ItemProperty -Path $key
    $backupFile = Join-Path $PSScriptRoot 'proxy-backup.json'
    @{
        ProxyEnable = $backup.ProxyEnable
        ProxyServer = $backup.ProxyServer
        ProxyOverride = $backup.ProxyOverride
    } | ConvertTo-Json | Set-Content -Path $backupFile -Encoding utf8

    Set-ItemProperty -Path $key -Name ProxyEnable -Value 1
    Set-ItemProperty -Path $key -Name ProxyServer -Value "127.0.0.1:$Port"
    # 本地与内网直连
    Set-ItemProperty -Path $key -Name ProxyOverride -Value 'localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>'

    # 通知 WinINET 配置已变更
    $sig = @'
[DllImport("wininet.dll", SetLastError = true, CharSet = CharSet.Auto)]
public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
'@
    $type = Add-Type -MemberDefinition $sig -Name WinINet -Namespace Native -PassThru
    [void]$type::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0)  # INTERNET_OPTION_SETTINGS_CHANGED
    [void]$type::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0)  # INTERNET_OPTION_REFRESH
    Write-Host "系统代理已设置为 127.0.0.1:$Port（原值已备份到 proxy-backup.json）"
}
elseif ($Disable) {
    $backupFile = Join-Path $PSScriptRoot 'proxy-backup.json'
    if (Test-Path $backupFile) {
        $b = Get-Content $backupFile -Raw | ConvertFrom-Json
        Set-ItemProperty -Path $key -Name ProxyEnable -Value ([int]$b.ProxyEnable)
        if ($null -ne $b.ProxyServer) { Set-ItemProperty -Path $key -Name ProxyServer -Value $b.ProxyServer }
        if ($null -ne $b.ProxyOverride) { Set-ItemProperty -Path $key -Name ProxyOverride -Value $b.ProxyOverride }
    } else {
        Set-ItemProperty -Path $key -Name ProxyEnable -Value 0
    }
    $sig = @'
[DllImport("wininet.dll", SetLastError = true, CharSet = CharSet.Auto)]
public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
'@
    $type = Add-Type -MemberDefinition $sig -Name WinINet2 -Namespace Native -PassThru
    [void]$type::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0)
    [void]$type::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0)
    Write-Host "系统代理已还原"
}
else { Write-Host "用法: -Enable -Port <port> | -Disable" }
