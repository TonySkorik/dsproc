using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using Newtonsoft.Json;

namespace Space.CertificateSerialization.DataModel
{
	[JsonObject("Certificate")]
	public sealed class X509CertificateSerializable
	{
		#region Props

		[JsonProperty("Subject")]
		public string SerializedSubject { get; }

		[JsonProperty("Issuer")]
		public string SerializedIssuer { get; }

		[JsonProperty("NotBefore")]
		public string SerializedNotBefore { get; }

		[JsonProperty("NotAfter")]
		public string SerializedNotAfter { get; }

		[JsonProperty("SerialNumber")]
		public string SerializedSerial { get; }

		[JsonProperty("Thumbprint")]
		public string SerializedThumbprint { get; }

		[JsonProperty("FriendlyName")]
		public string SerializedFriendlyName { get; }

		[JsonProperty("Version")]
		public int Version { get; }

		[JsonProperty("Certificates")]
		public List<X509CertificateSerializable> Certificates { get; }

		#endregion

		#region Ctor

		public X509CertificateSerializable(X509Certificate2 certificate)
		{
			SerializedSubject = certificate.Subject?.Replace("\"\"", "\"").Replace("\"", "\'");
			SerializedIssuer = certificate.Issuer?.Replace("\"\"", "\"").Replace("\"", "\'");
			SerializedNotBefore = certificate.NotBefore.ToString("s").Replace("T", " ");
			SerializedNotAfter = certificate.NotAfter.ToString("s").Replace("T", " ");
			SerializedSerial = certificate.SerialNumber;
			SerializedThumbprint = certificate.Thumbprint;
			SerializedFriendlyName = !string.IsNullOrEmpty(certificate.FriendlyName)
				? certificate.FriendlyName
				: null;
			Version = certificate.Version;
			Certificates = null;
		}

		public X509CertificateSerializable(X509Certificate2Collection collection)
		{
			Certificates = new List<X509CertificateSerializable>();
			foreach (X509Certificate2 cert in collection)
			{
				Certificates.Add(new X509CertificateSerializable(cert));
			}
		}

		#endregion
	}
}