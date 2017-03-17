using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Linq;

namespace Space.Core.Interfaces {
	public interface ICertificateProcessor
	{
		X509Certificate2 SearchCertificateByThumbprint(string certificateThumbprint);
		X509Certificate2 GetCertificateByThumbprint(string thumbprint, StoreLocation storeLocation);
		List<X509Certificate2> GetAllCertificatesFromStore(StoreLocation storeLocation);
		X509Certificate2 SelectCertificateUi(StoreLocation storeLocation);

		X509Certificate2 ReadCertificateFromXml(string signedXmlPath, string nodeId);
		X509Certificate2 ReadCertificateFromXmlDocument(XDocument signedXml, string nodeId);

		bool IsCertificateExpired(X509Certificate2 cert);
		bool MessageIsSmev2Base(XDocument message);
	}
}
