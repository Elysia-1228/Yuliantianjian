@echo off
chcp 65001 >nul
title 御链天鉴 - 一键启动

echo ================================================
echo       御链天鉴 - 网络安全智能分析平台
echo       一键启动前后端服务
echo ================================================
echo.

:: 设置环境变量
set JAVA_HOME=E:\JAVE JDK17
set PATH=C:\apache-maven-3.9.6\bin;%JAVA_HOME%\bin;%PATH%

:: 获取脚本所在目录
set PROJECT_DIR=%~dp0

echo [1/2] 正在启动后端服务 (端口 8985)...
cd /d "%PROJECT_DIR%BackCode"
start "后端服务 - 端口8985" cmd /k "set JAVA_HOME=E:\JAVE JDK17 && set PATH=C:\apache-maven-3.9.6\bin;%JAVA_HOME%\bin;%PATH% && mvn spring-boot:run -DskipTests"

echo [2/2] 正在启动前端服务 (端口 3000)...
cd /d "%PROJECT_DIR%FrontCode"
start "前端服务 - 端口3000" cmd /k "npm run dev"

echo.
echo ================================================
echo   启动完成！
echo   前端地址: http://localhost:3000
echo   后端地址: http://localhost:8985
echo   默认账号: admin / admin123
echo ================================================
echo.
echo 按任意键关闭此窗口...
pause >nul
