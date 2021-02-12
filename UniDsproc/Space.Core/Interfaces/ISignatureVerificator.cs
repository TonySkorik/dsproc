using System.Security.Cryptography;
using System.Xml;
using Space.Core.Configuration;

namespace Space.Core.Interfaces
{
	public interface ISignatureVerificator
	{
		bool VerifySignature(
			SignatureType mode,
			string documentPath,
			string certificateFilePath = null,
			string certificateThumb = null,
			string nodeId = null);

		bool VerifySignature(
			SignatureType mode,
			XmlDocument message,
			string certificateFilePath = null,
			string certificateThumb = null,
			string nodeId = null);

		(bool IsSignatureValid, string Message) VerifyDetachedSignature(byte[] signedFileBytes, byte[] signatureFileBytes);

		bool CheckSignatureDs(XmlDocument xmlDoc, RSACryptoServiceProvider key);
	}
}
