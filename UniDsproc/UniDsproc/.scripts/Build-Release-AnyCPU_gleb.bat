cls

pushd ..\..\..\
git pull

::pause

popd

"C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\MSBuild\Current\Bin\MSBuild.exe" /property:Configuration=Release;Platform=AnyCPU ..\UniDsproc.csproj