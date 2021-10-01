[Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding("utf-8")

$cert1 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate $args[0] 
$cert2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $cert1


#$sigAlg = [System.Security.Cryptography.Oid]$cert2.SignatureAlgorithm

#Write-Host "    Friendly name : " -NoNewline

Write-Host 'SignatureAlgorithm.FriendlyName : ' -NoNewline

if($cert2.SignatureAlgorithm.FriendlyName -ne $null -and $cert2.SignatureAlgorithm.FriendlyName -ne ""){

	Write-Host $cert2.SignatureAlgorithm

}else{
	Write-Host ''
}

# OID - идентификатор объектов

#Write-Host "    OID : " -NoNewline
#Write-Host $cert2.SignatureAlgorithm.Value

Write-Host 'SignatureAlgorithm.OID : ' -NoNewline
Write-Host $cert2.SignatureAlgorithm.Value


Write-Host "Extensions.KeyUsages : " -NoNewline

foreach ($certExt in $cert2.Extensions) {

   if( $certExt.GetType() -eq [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension] ) {

       $keyUsageExt = [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension] $certExt

       Write-Host $keyUsageExt.KeyUsages

   }
}
