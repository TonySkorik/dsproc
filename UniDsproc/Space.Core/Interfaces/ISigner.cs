using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Xml.Linq;
using Space.Core.Communication;
using Space.Core.Configuration;
using Space.Core.Infrastructure;

namespace Space.Core.Interfaces
{
	public interface ISigner
	{
		string Sign(
			SignatureType mode,
			GostFlavor gostFlavor,
			string certificateThumbprint,
			string signThisPath,
			bool assignDs,
			string nodeToSign,
			bool ignoreExpiredCert = false,
			bool? isAddSigningTime = null);

		string Sign(
			SignatureType mode,
			GostFlavor gostFlavor,
			XDocument signThis,
			string certificateThumbprint,
			string nodeToSign,
			bool assignDs = false,
			bool ignoreExpiredCert = false,
			bool? isAddSigningTime = null);

		string Sign(
			SignatureType mode,
			GostFlavor gostFlavor,
			XmlDocument signThis,
			string certificateThumbprint,
			string nodeToSign,
			bool assignDs = false,
			bool ignoreExpiredCert = false,
			bool? isAddSigningTime = null);

		SignerResponse Sign(
			SignatureType mode,
			GostFlavor gostFlavor,
			string certificateThumbprint,
			byte[] bytesToSign,
			string nodeToSign,
			bool ignoreExpiredCert = false,
			bool? isAddSigningTime = null);
	}
}
