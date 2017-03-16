using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace Space.Core.Interfaces {
	public interface ISigner {
		string Sign(
			Signer.SignatureType mode,
			X509Certificate2 cert,
			XmlDocument signThis,
			bool assignDs,
			string nodeToSign,
			string stringToSign = null);
	}
}
