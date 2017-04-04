using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace Space.Core.Interfaces
{
	public interface ISigner
	{
		string Sign(
			Signer.SignatureType mode,
			string certificateThumbprint,
			string signThisPath,
			bool assignDs,
			string nodeToSign,
			bool ignoreExpiredCert = false);

	}
}
