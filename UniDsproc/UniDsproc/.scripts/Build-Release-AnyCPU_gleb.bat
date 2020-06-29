cls

pushd ..\..\..\
git pull

::pause

cd UniDsproc

popd

REM "C:\Program Files (x86)\Microsoft Visual Studio\2017\Enterprise\MSBuild\15.0\Bin\MSBuild.exe" /property:Configuration=Release;Platform=AnyCPU ..\UniDsproc.csproj.csproj
"C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\MSBuild\15.0\Bin\MSBuild.exe" /property:Configuration=Release;Platform=AnyCPU ..\UniDsproc.csproj.csproj

cd ..\bin\Release
