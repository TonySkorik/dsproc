[Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding("utf-8")


$cert1 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate $args[0]

#Write-Output $args[0]
#Write-Output "*BEGIN*"

#$cert1 | foreach {New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $_} | Format-Custom *


#$cert1 | foreach {New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $_} | fl * -f

$cert2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $cert1

$cert2 | fl * 

#$cert2 | Get-Member | Select-Object

#$cert2 | fl * | ConvertTo-Xml  -As stream -Depth 10

# с ходу не получилось получить xml / json 
#$cert1 | foreach {New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $_} | ConvertTo-Xml -InputObject * -As string -Depth 10


#Write-Output "*END*"
