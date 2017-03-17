using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using Newtonsoft.Json;

namespace Space.CertificateSerialization.DataModel
{
	[JsonObject("Certificate")]
	public sealed class X509CertificateSerializable {
		[JsonProperty("Subject")]
		public string SerializedSubject;

		[JsonProperty("Issuer")]
		public string SerializedIssuer;

		[JsonProperty("NotBefore")]
		public string SerializedNotBefore;

		[JsonProperty("NotAfter")]
		public string SerializedNotAfter;

		[JsonProperty("SerialNumber")]
		public string SerializedSerial;

		[JsonProperty("Thumbprint")]
		public string SerializedThumbprint;

		[JsonProperty("FriendlyName")]
		public string SerializedFriendlyName;

		[JsonProperty("Version")]
		public int Version;

		[JsonProperty("Certificates")]
		public List<X509CertificateSerializable> Certificates;

		public X509CertificateSerializable(X509Certificate2 cer) {
			SerializedSubject = cer.Subject;
			SerializedIssuer = cer.Issuer;
			SerializedNotBefore = cer.NotBefore.ToString("s").Replace("T", " ");
			SerializedNotAfter = cer.NotAfter.ToString("s").Replace("T", " ");
			SerializedSerial = cer.SerialNumber;
			SerializedThumbprint = cer.Thumbprint;
			SerializedFriendlyName = !string.IsNullOrEmpty(cer.FriendlyName)? cer.FriendlyName : null;
			Version = cer.Version;
			Certificates = null;
		}

		public X509CertificateSerializable(X509Certificate2Collection collection) {
			Certificates = new List<X509CertificateSerializable>();
			foreach (X509Certificate2 cert in collection) {
				Certificates.Add(new X509CertificateSerializable(cert));
			}
		}
	}
}