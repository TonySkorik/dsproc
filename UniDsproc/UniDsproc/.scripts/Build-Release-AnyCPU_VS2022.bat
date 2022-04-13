cls

pushd ..\..\..\
git pull

::pause

popd

"c:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe" /property:Configuration=Release;Platform=AnyCPU ..\UniDsproc.csproj

pause