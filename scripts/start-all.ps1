# 御链天鉴 - 一键启动脚本 (PowerShell版)
# 使用方法: 在项目根目录运行 .\start-all.ps1

$Host.UI.RawUI.WindowTitle = "御链天鉴 - 一键启动"

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "      御链天鉴 - 网络安全智能分析平台" -ForegroundColor Green
Write-Host "      一键启动前后端服务" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# 设置环境变量
$env:JAVA_HOME = "E:\JAVE JDK17"
$env:PATH = "C:\apache-maven-3.9.6\bin;$env:JAVA_HOME\bin;$env:PATH"

# 获取脚本所在目录
$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "[1/2] 正在启动后端服务 (端口 8985)..." -ForegroundColor Yellow
$backendPath = Join-Path $ProjectDir "BackCode"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$backendPath'; `$env:JAVA_HOME='E:\JAVE JDK17'; `$env:PATH='C:\apache-maven-3.9.6\bin;'+`$env:JAVA_HOME+'\bin;'+`$env:PATH; mvn spring-boot:run -DskipTests"

Write-Host "[2/2] 正在启动前端服务 (端口 3000)..." -ForegroundColor Yellow
$frontendPath = Join-Path $ProjectDir "FrontCode"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$frontendPath'; npm run dev"

Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  启动完成！" -ForegroundColor Green
Write-Host "  前端地址: http://localhost:3000" -ForegroundColor White
Write-Host "  后端地址: http://localhost:8985" -ForegroundColor White
Write-Host "  默认账号: admin / admin123" -ForegroundColor White
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "按任意键关闭此窗口..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
