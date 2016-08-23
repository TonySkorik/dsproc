using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using UniDsproc.SignatureProcessor;

namespace UniDsproc.DataModel {
	[DataContract(Name = "result")]
	public class ResultInfo:PrintableInfo {

		[DataMember(Name = "message")]
		public string Message { get; }

		[JsonProperty("certificate",DefaultValueHandling = DefaultValueHandling.Ignore)]
		public X509CertificateSerializabale Certificate { get; }

		[JsonProperty("signature_is_ok",DefaultValueHandling = DefaultValueHandling.Include)]
		[JsonConverter(typeof(BoolToIntConverter))]
		public bool SignatureIsCorrect { get; }

		public ResultInfo(string msg) {
			Message = msg;
			Certificate = null;
			SignatureIsCorrect = false;
		}

		public ResultInfo(X509CertificateSerializabale cert) {
			Message = "Certificate data extracted";
			Certificate = cert;
			SignatureIsCorrect = false;
		}

		public ResultInfo(string msg, bool signatureIsCorrect) {
			Message = msg;
			Certificate = null;
			SignatureIsCorrect = signatureIsCorrect;
		}
	}
}
