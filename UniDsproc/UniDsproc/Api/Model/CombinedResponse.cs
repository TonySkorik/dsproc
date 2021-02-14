using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Space.Core.Communication;

namespace UniDsproc.Api.Model
{
	public class CombinedResponse
	{
		public VerifierResponse VerificationResult { set; get; }
		public X509CertificateSerializable ExtractedCertificate { set; get; }
	}
}
