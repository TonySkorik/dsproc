using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Linq;
using Space.Core.Interfaces;

namespace Space.Core.Processor
{
	public static partial class CertificateUtils
	{
		/// <summary>
		/// Determines wheter certificate is expired
		/// </summary>
		/// <param name="certificate"><see cref="X509Certificate2"/> to analyze</param>
		public static bool IsCertificateExpired(X509Certificate2 certificate)
		{
			if (certificate == null)
			{
				return true;
			}

			DateTime dtNow = DateTime.Now.ToUniversalTime();
			return !(dtNow > certificate.NotBefore.ToUniversalTime() && dtNow < certificate.NotAfter.ToUniversalTime());
		}

		/// <summary>
		/// Determines wheter passed document is built in Smev2 manner (has Header and wsse:Security elements)
		/// </summary>
		/// <param name="document"><see cref="XDocument"/> to analyze</param>
		public static bool MessageIsSmev2Base(XDocument document)
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
	}
}
