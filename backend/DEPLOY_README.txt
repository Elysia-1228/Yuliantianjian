================================================================================
              BACKEND (BLOCKCHAIN GATEWAY) DEPLOYMENT GUIDE
================================================================================

1. DEPLOYMENT STRUCTURE (Recommended)
   You asked for "Package and Jar in the same level" -> YES, IT IS SUPPORTED NOW!
   
   Create a folder on your server (e.g., /opt/zhilian/backend) and upload:
   
   /opt/zhilian/backend/
   ├── backend-0.0.1-SNAPSHOT.jar   <-- The executable jar
   ├── start_server.bat             <-- The startup script I created for you
   └── Zhilian_Install_Package/     <-- The folder containing fabric network files
       └── fabric-network/...

2. HOW TO RUN
   Simply run the start script:
   
   Windows: start_server.bat
   Linux:   java -jar backend-0.0.1-SNAPSHOT.jar --FABRIC_PKG=.

   This command tells the application to look for configuration files in the 
   CURRENT directory (.) instead of the parent directory (../).

3. PORT & SECURITY
   - Port: 8986
   - API Key: secret-api-key (Header: X-API-KEY)

================================================================================
