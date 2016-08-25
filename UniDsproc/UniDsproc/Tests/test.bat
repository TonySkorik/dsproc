@echo off
echo UniDsproc testing suite.
echo ------------------------

SET thumb=%1
SET dsproc=%2

::SET thumb="f0 43 bb 22 44 ad 2e 45 87 ae 7c b9 4d 5d bf 3d 45 09 c6 65"
::SET dsproc="d:\!_Coding\!_Win\C#\!_UNIDSPROC\UniDsproc\UniDsproc\bin\Debug\UniDsproc.exe"

echo %thumb%
echo %dsproc%
::==================================================================SIGNING
echo Testing signing
echo ------------------------
echo smev2_sidebyside.detached
	%dsproc% sign -ignore_expired=true -signature_type=smev2_sidebyside.detached -thumbprint=%thumb% -node_id="SIGNED_BY_SERVER" smev2.sidebyside.xml smev2.sidebyside.signed.xml
pause
echo ------------------------
echo smev2_charge.enveloped
	%dsproc% sign -ignore_expired=true -signature_type=smev2_charge.enveloped -thumbprint=%thumb% smev2.charge.xml smev2.charge.signed.xml
pause
echo ------------------------
echo smev2_base.detached
	%dsproc% sign -ignore_expired=true -signature_type=smev2_base.detached -thumbprint=%thumb% smev2.base.xml smev2.base.signed.xml
pause
echo ------------------------
echo smev3_base.detached
	%dsproc% sign -ignore_expired=true -signature_type=smev3_base.detached -thumbprint=%thumb% -node_id="SIGNED_BY_SERVER" smev3.base.xml smev3.base.signed.xml
pause
echo ------------------------
echo smev3_sidebyside.detached
	%dsproc% sign -ignore_expired=true -signature_type=smev3_sidebyside.detached -thumbprint=%thumb% -node_id="SIGNED_BY_SERVER" smev3.sidebyside.xml smev3.sidebyside.signed.xml
pause
echo ------------------------
echo smev3_ack
	%dsproc% sign -ignore_expired=true -signature_type=smev3_ack -thumbprint=%thumb% -node_id="SIGNED_BY_SERVER" smev3.ack.xml smev3.ack.signed.xml
pause
echo ------------------------
::==================================================================EXTRACTION
echo Testing certificate extraction
pause
echo ------------------------
echo extract from XML
	%dsproc% extract -certificate_source=xml -node_id="SIGNED_BY_SERVER" smev2.sidebyside.signed.xml
pause
echo ------------------------
echo extract from base64
	%dsproc% extract -certificate_source=base64 base64.txt
pause
echo ------------------------
echo extract from cer base64 encoding
	%dsproc% extract -certificate_source=cer base_64_cert.cer
pause
echo ------------------------
echo extract from cer DER encoding
	%dsproc% extract -certificate_source=cer der_cert.cer
pause
echo ------------------------
echo extract from cer PKCS#7
	%dsproc% extract -certificate_source=cer pkcs_cert.p7b
pause
echo ------------------------
echo extract from cer PKCS#7 multiple certs in container
	%dsproc% extract -certificate_source=cer rptr_pkcs.p7b
pause
echo ------------------------
::==================================================================VERIFICATION
echo Testing signature verification
pause
echo ------------------------
echo smev2_sidebyside.detached
	%dsproc% verify -signature_type=smev2_sidebyside.detached -node_id="SIGNED_BY_SERVER" smev2.sidebyside.signed.xml
pause
echo ------------------------
echo smev2_charge.enveloped
	%dsproc% verify -signature_type=smev2_charge.enveloped smev2.charge.signed.xml
pause
echo ------------------------
echo smev2_base.datached
	%dsproc% verify -signature_type=smev2_base.datached smev2.base.signed.xml
pause
echo ------------------------
echo smev3_base.detached
	%dsproc% verify -signature_type=smev3_base.detached -node_id="SIGNED_BY_SERVER" smev3.base.signed.xml
pause
echo ------------------------
echo smev3_sidebyside.detached
	%dsproc% verify -signature_type=smev3_sidebyside.detached -node_id=SIGNED_BY_SERVER smev3.sidebyside.signed.xml
pause
echo ------------------------
echo smev3_ack
	%dsproc% verify -signature_type=smev3_ack -node_id="SIGNED_BY_SERVER" smev3.ack.signed.xml
pause
echo ------------------------
::==================================================================VERIFY AND EXTRACT
echo Testing signature verification AND extraction
pause
echo ------------------------
echo smev2_sidebyside.detached
	%dsproc% verifyAndExtract -signature_type=smev2_sidebyside.detached -node_id="SIGNED_BY_SERVER" smev2.sidebyside.signed.xml
pause
echo ------------------------
echo smev2_charge.enveloped
	%dsproc% verifyAndExtract -signature_type=smev2_charge.enveloped smev2.charge.signed.xml
pause
echo ------------------------
echo smev2_base.datached
	%dsproc% verifyAndExtract -signature_type=smev2_base.datached smev2.base.signed.xml
pause
echo ------------------------
echo smev3_base.detached
	%dsproc% verifyAndExtract -signature_type=smev3_base.detached -node_id="SIGNED_BY_SERVER" smev3.base.signed.xml
pause
echo ------------------------
echo smev3_sidebyside.detached
	%dsproc% verifyAndExtract -signature_type=smev3_sidebyside.detached -node_id="SIGNED_BY_SERVER" smev3.sidebyside.signed.xml
pause
echo ------------------------
echo smev3_ack
	%dsproc% verifyAndExtract -signature_type=smev3_ack -node_id="SIGNED_BY_SERVER" smev3.ack.signed.xml
pause
echo ------------------------
echo DONE.
pause