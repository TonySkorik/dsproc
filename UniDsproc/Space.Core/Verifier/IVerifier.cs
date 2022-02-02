﻿using Space.Core.Communication;
using Space.Core.Model.SignedFile;

namespace Space.Core.Verifier
{
	public interface IVerifier
	{
		VerifierResponse Verify(SignedXmlFile signedFile, SignatureVerificationParameters parameters);

		VerifierResponse Verify(SignedDetachedSignatureFile signedFile, SignatureVerificationParameters parameters);
	}
}
