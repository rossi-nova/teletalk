@echo off
chcp 65001 >nul
echo ========================================
echo   teletalk 登录态抓取
echo ========================================
echo.
echo 本脚本会：
echo   1. 启动 MITM 代理（只拦截 tls-desktop.dingtalk.com）
echo   2. 提示你重启钉钉
echo   3. 你正常使用/登录钉钉
echo   4. 从中提取 token 写入网关配置
echo.
echo 按任意键开始...
pause >nul

set ROOT=%~dp0..
set MITM=%ROOT%\tools\mitm
set CAP=%ROOT%\captures

echo.
echo [1/3] 启动 MITM 代理...
start "teletalk-mitm" cmd /c "cd /d %MITM% && node proxy.mjs --port 8888"

timeout /t 3 >nul

echo.
echo [2/3] 请现在打开 Clash Verge：
echo       - 确认 teletalk-capture 组指向 teletalk-mitm
echo       - 若未配置，先粘贴 tools\mitm\clash\teletalk-merge.yaml
echo.
echo       然后重启钉钉（含托盘图标）。
echo.
echo 按任意键继续...
pause >nul

echo.
echo [3/3] 等待抓包...（30 秒后自动提取）
timeout /t 30 >nul

echo.
echo 提取 token...
cd /d %ROOT%
npx tsx tools/extract-token.ts "%CAP%"

echo.
echo 完成。现在可以：
echo   - 关闭 MITM 代理窗口
echo   - 把 Clash 的 teletalk-capture 切回 DIRECT
echo   - 启动网关：pnpm --filter @teletalk/server dev
echo.
pause
