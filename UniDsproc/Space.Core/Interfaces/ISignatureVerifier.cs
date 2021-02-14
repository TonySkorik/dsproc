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
			string documentPath,
			string certificateFilePath = null,
			string certificateThumb = null,
			string nodeId = null);

		VerifierResponse VerifySignature(
			SignatureType mode,
			XmlDocument message,
			string certificateFilePath = null,
			string certificateThumb = null,
			string nodeId = null);

		VerifierResponse VerifyDetachedSignature(byte[] signedFileBytes, byte[] signatureFileBytes);

		VerifierResponse CheckSignatureDs(XmlDocument xmlDoc, RSACryptoServiceProvider key);
	}
}
