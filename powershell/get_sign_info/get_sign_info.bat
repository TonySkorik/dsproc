@echo off

::E:
::cd E:\home\vhosts\gsen\corp\cgi-bin\ps\get_sign_info\

:: get_cert_info.bat "полное имя файла"

::powershell -OutputFormat Text -File E:\home\vhosts\gsen\corp\cgi-bin\ps\get_cert_info\get_cert_info.ps1 "%1"
powershell .\get_sign_info.ps1 %1
