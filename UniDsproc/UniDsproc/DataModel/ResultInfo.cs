using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace UniDsproc.DataModel {
	[DataContract(Name = "result")]
	public class ResultInfo:PrintableInfo {

		[DataMember(Name = "message")]
		public string Message { get; }

		[JsonProperty("certificate",DefaultValueHandling = DefaultValueHandling.Ignore)]
		[JsonConverter(typeof(CertToJsonConverter))]
		public X509Certificate2 Certificate { get; }

		public ResultInfo(string msg) {
			Message = msg;
			Certificate = null;
		}

		public ResultInfo(X509Certificate2 cert) {
			Message = "Certificate data extracted";
			Certificate = cert;
		}
	}
}
