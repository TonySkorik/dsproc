using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Xml.Linq;
using Space.Core.Configuration;

namespace Space.Core.Interfaces
{
	public interface ISigner
	{
		string Sign(
			SignatureType mode,
			string certificateThumbprint,
			string signThisPath,
			bool assignDs,
			string nodeToSign,
			bool ignoreExpiredCert = false);

		string Sign(
			SignatureType mode,
			XDocument signThis,
			string certificateThumbprint,
			string nodeToSign,
			bool assignDs = false,
			bool ignoreExpiredCert = false);

	}
}
