using System.Security.Cryptography;
using System.Xml;
using Space.Core.Communication;
using Space.Core.Configuration;
using Space.Core.Model;
using Space.Core.Model.SignedFile;

namespace Space.Core.Interfaces
{
	public interface ISignatureVerifier
	{
		VerifierResponse VerifySignature(InputDataBase signedFile);

		VerifierResponse VerifySignature(
			SignatureType mode,
			string documentPath = null,
			string certificateFilePath = null,
			string certificateThumb = null,
			string nodeId = null, 
			byte[] signedFileBytes = null,
			byte[] signatureFileBytes = null,
			bool isVerifyCertificateChain = false);

		VerifierResponse CheckSignatureDs(XmlDocument xmlDoc, RSACryptoServiceProvider key);
	}
}
