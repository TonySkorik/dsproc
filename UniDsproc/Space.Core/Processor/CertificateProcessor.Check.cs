using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Linq;
using Space.Core.Interfaces;

namespace Space.Core.Processor
{
	public partial class CertificateProcessor : ICertificateProcessor
	{
		#region Checks

		public bool IsCertificateExpired(X509Certificate2 certificate)
		{
			if (certificate == null)
			{
				return true;
			}

			DateTime dtNow = DateTime.Now.ToUniversalTime();
			return !(dtNow > certificate.NotBefore.ToUniversalTime() && dtNow < certificate.NotAfter.ToUniversalTime());
		}

		public bool MessageIsSmev2Base(XDocument document)
		{
			XNamespace wsse = Signer.WsSecurityWsseNamespaceUrl;
			XNamespace env = "http://schemas.xmlsoap.org/soap/envelope/";
			try
			{
				return document.Root?.Descendants(env + "Header").First().Descendants(wsse + "Security").Any()
					?? false;
			}
			catch
			{
				return false;
			}
		}

		#endregion
	}
}
