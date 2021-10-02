[Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding("windows-1251")
#[Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding("utf-8")

$singatureFileBytes = [System.IO.File]::ReadAllBytes($args[0])
$singedCms = New-Object System.Security.Cryptography.Pkcs.SignedCms
$singedCms.Decode($singatureFileBytes)

foreach($cert in $singedCms.Certificates){
	Write-Host 'Subject : ' -NoNewline
	Write-Host $cert.Subject

	Write-Host 'Issuer : ' -NoNewline
	Write-Host $cert.Issuer

	Write-Host 'Thumbprint : ' -NoNewline
	Write-Host $cert.Thumbprint

	Write-Host 'Serial Number : ' -NoNewline
	Write-Host $cert.SerialNumber

	Write-Host 'Not before : ' -NoNewline
	Write-Host $cert.NotBefore

	Write-Host 'Not after : ' -NoNewline
	Write-Host $cert.NotAfter
	
	Write-Host 'SignatureAlgorithm--FriendlyName : ' -NoNewline
	if($cert.SignatureAlgorithm.FriendlyName -ne $null -and $cert.SignatureAlgorithm.FriendlyName -ne ''){
		Write-Host $cert.SignatureAlgorithm
	}else{
		Write-Host ''
	}

	Write-Host 'SignatureAlgorithm--OID : ' -NoNewline
	Write-Host $cert.SignatureAlgorithm.Value

	Write-Host "Extensions--KeyUsages : " -NoNewline
	foreach ($certExt in $cert.Extensions) {
		if( $certExt.GetType() -eq [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension] ) {
			$keyUsageExt = [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension] $certExt
			Write-Host $keyUsageExt.KeyUsages
		}
	}
}
