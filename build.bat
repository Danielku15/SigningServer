@echo OFF
set msbuild_exe=msbuild.exe

where %msbuild_exe%
if errorlevel 0 goto alreadyinpath
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\Common7\Tools\VsDevCmd.bat"
:alreadyInPath

echo "Building x64/AnyCpu (Debug)"
%msbuild_exe% SigningServer.sln -restore:true -p:Configuration=Debug

echo "Building x64/AnyCpu (Release)"
%msbuild_exe% SigningServer.sln -restore:true -p:Configuration=Release
