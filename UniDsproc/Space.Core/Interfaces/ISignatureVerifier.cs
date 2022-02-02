using Space.Core.Communication;
using Space.Core.Model;
using Space.Core.Verifier;

namespace Space.Core.Interfaces
{
	public interface ISignatureVerifier
	{
		VerifierResponse VerifySignature(InputDataBase signedFile, SignatureVerificationParameters parameters);
	}
}
