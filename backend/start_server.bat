@echo off
echo [INFO] Starting Backend (Blockchain Gateway)...
echo [INFO] Mode: SAME DIRECTORY (Jar and Package are in the same folder)

if not exist "Zhilian_Install_Package" (
    echo [ERROR] Could not find 'Zhilian_Install_Package' in the current directory!
    echo [ERROR] Please make sure you copied the 'Zhilian_Install_Package' folder here.
    pause
    exit /b 1
)

:: 使用 --FABRIC_PKG=. 参数指定当前目录
java -Dotel.traces.exporter=none -Dotel.metrics.exporter=none -Dotel.logs.exporter=none -jar backend-0.0.1-SNAPSHOT.jar --FABRIC_PKG=.
pause
