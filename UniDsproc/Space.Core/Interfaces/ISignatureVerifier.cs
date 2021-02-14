using System.Security.Cryptography;
using System.Xml;
using Space.Core.Communication;
using Space.Core.Configuration;

namespace Space.Core.Interfaces
{
	public interface ISignatureVerifier
	{
		VerifierResponse VerifySignature(
			SignatureType mode,
			string documentPath = null,
			string certificateFilePath = null,
			string certificateThumb = null,
			string nodeId = null, 
			byte[] signedFileBytes = null,
			byte[] signatureFileBytes = null);

		VerifierResponse CheckSignatureDs(XmlDocument xmlDoc, RSACryptoServiceProvider key);
	}
}
