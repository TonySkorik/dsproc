using System.Runtime.Serialization;
using Newtonsoft.Json;
using Space.CertificateSerialization.DataModel;

namespace UniDsproc.DataModel {
	[DataContract(Name = "result")]
	public class ResultInfo:PrintableInfo {

		[DataMember(Name = "message")]
		public string Message { get; }

		[JsonProperty("certificate",DefaultValueHandling = DefaultValueHandling.Ignore)]
		public X509CertificateSerializable Certificate { get; }

		[JsonProperty("signature_is_ok",DefaultValueHandling = DefaultValueHandling.Ignore)]
		[JsonConverter(typeof(BoolToIntConverterNullable))]
		public bool? SignatureIsCorrect { get; }

		public ResultInfo(string msg) {
			Message = msg;
			Certificate = null;
			SignatureIsCorrect = null;
		}

		public ResultInfo(X509CertificateSerializable cert) {
			Message = "Certificate data extracted";
			Certificate = cert;
			SignatureIsCorrect = null;
		}

		public ResultInfo(string msg, bool signatureIsCorrect) {
			Message = msg;
			Certificate = null;
			SignatureIsCorrect = signatureIsCorrect;
		}
	}
}
