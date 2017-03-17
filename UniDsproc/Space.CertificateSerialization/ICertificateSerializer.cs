using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Space.CertificateSerialization.DataModel;
using Space.Core;

namespace Space.CertificateSerialization
{
	public interface ICertificateSerializer
	{
		X509CertificateSerializable CertificateToSerializableCertificate(
			CertificateProcessor.CertificateSource source,
			string filePath,
			string nodeId);
	}
}
