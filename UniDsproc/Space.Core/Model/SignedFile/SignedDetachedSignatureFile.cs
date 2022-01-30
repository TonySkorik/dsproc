using System;
using Space.Core.Communication;
using Space.Core.Verifier;

namespace Space.Core.Model.SignedFile
{
	public class SignedDetachedSignatureFile : InputDataBase
	{
		public DateTime? SigningDateTime { get; set; }

		public override VerifierResponse Verify(IVerifier verifier, SignatureVerificationParameters parameters)
		{
			return verifier.Verify(this, parameters);
		}
	}
}
