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

		public ResultInfo(string msg) {
			Message = msg;
			Certificate = null;
		}

		public ResultInfo(X509CertificateSerializabale cert) {
			Message = "Certificate data extracted";
			Certificate = cert;
		}
	}
}
