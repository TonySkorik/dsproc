using Space.Core.DataModel;

namespace Space.Core.Interfaces {
	public interface ICertificateProcessor {
		X509CertificateSerializable CertificateToSerializableCertificate(
			CertificateProcessor.CertificateSource source,
			string filePath,
			string nodeId);
	}
}
