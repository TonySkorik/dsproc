using Space.Core.Communication;
using Space.Core.Interfaces;
using Space.Core.Model;

namespace Space.Core.Verifier
{
	public class SignatureVerifier : ISignatureVerifier
	{
		private readonly IVerifier _verifier = new DigitalSignatureVerifier();

		public VerifierResponse VerifySignature(InputDataBase signedFile,SignatureVerificationParameters parameters)
		{
			return signedFile.Verify(_verifier, parameters);
		}
	}
}
