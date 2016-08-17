using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace dsproc.DataModel {
	[DataContract(Name = "status")]
	public class StatusInfo: IJsonable {

		[DataMember(Name = "is_error")]
		public bool IsError { get; }
		[DataMember(Name = "error")]
		public ErrorInfo Error { set; get; }
		[DataMember(Name = "result")]
		public string Result { get; }

		public string ToJsonString() {
			return JsonConvert.SerializeObject(this, Formatting.Indented);
		}

		public StatusInfo(ErrorInfo errorInfo) {
			Result = null;
			IsError = true;
			Error = errorInfo;
		}

		public StatusInfo(string result) {
			Result = result;
			IsError = false;
			Error = null;
		}
	}
}
