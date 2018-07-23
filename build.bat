@echo OFF
set msbuild_exe="C:\Program Files (x86)\Microsoft Visual Studio\2017\Professional\MSBuild\15.0\Bin\MSBuild.exe"
if not exist %msbuild_exe% echo error: %msbuild_exe%: not found & goto :eof

echo "Building 32 bit (Debug)"
%msbuild_exe% SigningServer.sln /p:Configuration=Debug /p:Platform=x86

echo "Building 64 bit (Debug)"
%msbuild_exe% SigningServer.sln /p:Configuration=Debug /p:Platform=x64

echo "Building 32 bit (Release)"
%msbuild_exe% SigningServer.sln /p:Configuration=Release /p:Platform=x86

echo "Building 64 bit (Release)"
%msbuild_exe% SigningServer.sln /p:Configuration=Release /p:Platform=x64