@echo off
echo UniDsproc testing suite.
echo ------------------------

SET thumb="f0 43 bb 22 44 ad 2e 45 87 ae 7c b9 4d 5d bf 3d 45 09 c6 65"
SET dsproc="d:\!_Coding\!_Win\C#\!_UNIDSPROC\UniDsproc\UniDsproc\bin\Debug\UniDsproc.exe"
echo %thumb%
echo %dsproc%
::==================================================================SIGNING
echo Testing signing
echo ------------------------
echo smev2_sidebyside.detached
%dsproc% sign -ignore_expired=true -signature_type=smev2_sidebyside.detached -thumbprint=%thumb% -node_id="SIGNED_BY_SERVER" private_config.xml signed_smev2_side_by_side.xml
pause
echo ------------------------
echo smev2_sidebyside.detached
	%dsproc% sign -ignore_expired=true -signature_type=smev2_base.detached -thumbprint=%thumb% private_config.xml signed_smev2_base.xml
echo ------------------------
echo smev2_sidebyside.detached
	%dsproc% sign -ignore_expired=true -signature_type=smev3_base.detached -thumbprint=%thumb% -node_id="SIGNED_BY_SERVER" private_config.xml signed_smev3_base.xml
echo ------------------------
pause
::==================================================================EXTRACTION
echo Testing certificate extraction
echo ------------------------
echo extract from XML
	%dsproc% extract -certificate_source=xml -node_id=SIGNED_BY_SERVER smev2.detached.signed.xml
echo ------------------------
echo extract from base64
	%dsproc% extract -certificate_source=base64 base64.txt
echo ------------------------
echo extract from cer base64 encoding
	%dsproc% extract -certificate_source=cer base_64_cert.cer
echo ------------------------
echo extract from cer DER encoding
	%dsproc% extract -certificate_source=cer der_cert.cer
echo ------------------------
echo extract from cer PKCS#7
	%dsproc% extract -certificate_source=cer pkcs_cert.p7b
echo ------------------------
echo extract from cer PKCS#7 multiple certs in container
	%dsproc% extract -certificate_source=cer rptr_pkcs.p7b
echo ------------------------
pause
::==================================================================VERIFICATION
echo Testing signature verification
echo ------------------------
echo smev2_sidebyside.detached
	%dsproc% verify -signature_type=smev2_sidebyside.detached -node_id=SIGNED_BY_SERVER smev2.detached.signed.xml
echo ------------------------
echo smev2_charge.enveloped
	%dsproc% verify -signature_type=smev2_charge.enveloped smev2.charge.signed.xml
echo ------------------------
echo smev3_base.detached
	%dsproc% verify -signature_type=smev3_base.detached -node_id=ID_SIGN smev3.base.signed.xml
echo ------------------------
echo DONE.