cls

pushd ..\..\..\
git pull

::pause

popd

"c:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" /property:Configuration=Release;Platform=AnyCPU ..\UniDsproc.csproj
