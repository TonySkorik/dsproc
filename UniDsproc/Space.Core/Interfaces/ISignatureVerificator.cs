using System.Security.Cryptography;
using System.Xml;

namespace Space.Core.Interfaces
{
	public interface ISignatureVerificator
	{
		bool VerifySignature(
			Signer.SignatureType mode,
			string documentPath,
			string certificateFilePath = null,
			string certificateThumb = null,
			string nodeId = null);

		bool VerifySignature(
			Signer.SignatureType mode,
			XmlDocument message,
			string certificateFilePath = null,
			string certificateThumb = null,
			string nodeId = null);

		bool CheckSignatureDs(XmlDocument xmlDoc, RSACryptoServiceProvider key);
	}
}
