using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace UniDsproc.DataModel {
	[DataContract(Name = "status")]
	public class StatusInfo: PrintableInfo {

		[JsonProperty("is_error",DefaultValueHandling = DefaultValueHandling.Include)]
		[JsonConverter(typeof(BoolToIntConverter))]
		public bool IsError { get; }

		[JsonProperty("error")]
		public ErrorInfo Error { set; get; }

		[DataMember(Name = "result")]
		public ResultInfo Result { get; }
		
		public StatusInfo(ErrorInfo errorInfo) {
			Result = null;
			IsError = true;
			Error = errorInfo;
		}

		public StatusInfo(string result) {
			Result = new ResultInfo(result);
			IsError = false;
			Error = null;
		}

		public StatusInfo(ResultInfo result) {
			Result = result;
			IsError = false;
			Error = null;
		}
	}
}
