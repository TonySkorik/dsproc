using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Space.Core.Communication;
using Space.Core.Model.SignedFile;

namespace Space.Core.Verifier
{
	public interface IVerifier
	{
		VerifierResponse Verify(SignedXmlFile signedFile, SignatureVerificationParameters parameters);
		VerifierResponse Verify(SignedDetachedSignatureFile signedFile, SignatureVerificationParameters parameters);
	}
}
