@echo OFF

where msbuild >nul 2>&1
if %errorlevel% equ 0 (
	goto compile	
)

echo Looking for VS2019 Professional
SET VS="C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\Common7\Tools\VsDevCmd.bat"
if EXIST %VS% (
	echo Found VS2019 Professional
	call %VS%
	goto compile
)

echo Looking for VS2019 Community
SET VS="C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\Tools\VsDevCmd.bat"
if EXIST %VS% (
	echo Found VS2019 Community
	call %VS%
	goto compile
) 


echo "Could not detect Visual Studio 2019"
exit 1

:compile

echo "Building x64 (Debug)"
msbuild SigningServer.sln -t:Rebuild -p:Configuration=Debug -p:Platform=x64 -p:CopyToDist=true

echo "Building x64 (Release)"
msbuild SigningServer.sln -t:Rebuild -p:Configuration=Release -p:Platform=x64 -p:CopyToDist=true
